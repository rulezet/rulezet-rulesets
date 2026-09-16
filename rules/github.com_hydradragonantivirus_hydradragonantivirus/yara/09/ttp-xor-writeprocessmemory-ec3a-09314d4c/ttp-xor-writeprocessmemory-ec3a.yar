rule TTP_XOR_WriteProcessMemory_ec3a {
  strings:
    $key_ec3a = { bb 48 [2] 89 6a [2] 8f 5f [2] a1 5f [2] 9e 43 }

  condition:
    any of them
}