rule TTP_XOR_WriteProcessMemory_ec4a {
  strings:
    $key_ec4a = { bb 38 [2] 89 1a [2] 8f 2f [2] a1 2f [2] 9e 33 }

  condition:
    any of them
}