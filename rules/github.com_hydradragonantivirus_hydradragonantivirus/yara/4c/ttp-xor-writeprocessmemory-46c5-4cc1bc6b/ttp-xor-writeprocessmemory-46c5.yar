rule TTP_XOR_WriteProcessMemory_46c5 {
  strings:
    $key_46c5 = { 11 b7 [2] 23 95 [2] 25 a0 [2] 0b a0 [2] 34 bc }

  condition:
    any of them
}