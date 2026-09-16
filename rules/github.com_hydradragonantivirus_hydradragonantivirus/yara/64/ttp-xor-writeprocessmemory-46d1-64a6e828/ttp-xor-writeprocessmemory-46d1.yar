rule TTP_XOR_WriteProcessMemory_46d1 {
  strings:
    $key_46d1 = { 11 a3 [2] 23 81 [2] 25 b4 [2] 0b b4 [2] 34 a8 }

  condition:
    any of them
}