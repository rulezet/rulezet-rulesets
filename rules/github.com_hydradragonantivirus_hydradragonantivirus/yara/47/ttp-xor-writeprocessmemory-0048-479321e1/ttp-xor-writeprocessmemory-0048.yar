rule TTP_XOR_WriteProcessMemory_0048 {
  strings:
    $key_0048 = { 57 3a [2] 65 18 [2] 63 2d [2] 4d 2d [2] 72 31 }

  condition:
    any of them
}