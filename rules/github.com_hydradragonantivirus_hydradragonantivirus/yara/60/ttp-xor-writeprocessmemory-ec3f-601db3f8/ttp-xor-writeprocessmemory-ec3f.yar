rule TTP_XOR_WriteProcessMemory_ec3f {
  strings:
    $key_ec3f = { bb 4d [2] 89 6f [2] 8f 5a [2] a1 5a [2] 9e 46 }

  condition:
    any of them
}