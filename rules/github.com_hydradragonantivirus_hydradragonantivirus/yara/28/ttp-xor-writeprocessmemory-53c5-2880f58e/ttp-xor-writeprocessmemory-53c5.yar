rule TTP_XOR_WriteProcessMemory_53c5 {
  strings:
    $key_53c5 = { 04 b7 [2] 36 95 [2] 30 a0 [2] 1e a0 [2] 21 bc }

  condition:
    any of them
}