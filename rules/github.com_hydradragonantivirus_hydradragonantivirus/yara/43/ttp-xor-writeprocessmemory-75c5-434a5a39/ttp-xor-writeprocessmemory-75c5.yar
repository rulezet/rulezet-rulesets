rule TTP_XOR_WriteProcessMemory_75c5 {
  strings:
    $key_75c5 = { 22 b7 [2] 10 95 [2] 16 a0 [2] 38 a0 [2] 07 bc }

  condition:
    any of them
}