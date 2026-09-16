rule TTP_XOR_WriteProcessMemory_1548 {
  strings:
    $key_1548 = { 42 3a [2] 70 18 [2] 76 2d [2] 58 2d [2] 67 31 }

  condition:
    any of them
}