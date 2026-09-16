rule TTP_XOR_WriteProcessMemory_46d4 {
  strings:
    $key_46d4 = { 11 a6 [2] 23 84 [2] 25 b1 [2] 0b b1 [2] 34 ad }

  condition:
    any of them
}