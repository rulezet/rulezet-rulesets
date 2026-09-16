rule TTP_XOR_WriteProcessMemory_46a0 {
  strings:
    $key_46a0 = { 11 d2 [2] 23 f0 [2] 25 c5 [2] 0b c5 [2] 34 d9 }

  condition:
    any of them
}