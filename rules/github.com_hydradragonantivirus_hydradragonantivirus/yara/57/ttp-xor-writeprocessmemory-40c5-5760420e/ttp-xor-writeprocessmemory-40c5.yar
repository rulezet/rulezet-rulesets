rule TTP_XOR_WriteProcessMemory_40c5 {
  strings:
    $key_40c5 = { 17 b7 [2] 25 95 [2] 23 a0 [2] 0d a0 [2] 32 bc }

  condition:
    any of them
}