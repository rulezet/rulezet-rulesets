rule TTP_XOR_WriteProcessMemory_47c5 {
  strings:
    $key_47c5 = { 10 b7 [2] 22 95 [2] 24 a0 [2] 0a a0 [2] 35 bc }

  condition:
    any of them
}