rule TTP_XOR_WriteProcessMemory_ec48 {
  strings:
    $key_ec48 = { bb 3a [2] 89 18 [2] 8f 2d [2] a1 2d [2] 9e 31 }

  condition:
    any of them
}