rule TTP_XOR_WriteProcessMemory_5248 {
  strings:
    $key_5248 = { 05 3a [2] 37 18 [2] 31 2d [2] 1f 2d [2] 20 31 }

  condition:
    any of them
}