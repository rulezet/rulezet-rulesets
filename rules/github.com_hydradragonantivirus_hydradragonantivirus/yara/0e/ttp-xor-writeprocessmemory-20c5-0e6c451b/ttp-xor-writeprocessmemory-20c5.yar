rule TTP_XOR_WriteProcessMemory_20c5 {
  strings:
    $key_20c5 = { 77 b7 [2] 45 95 [2] 43 a0 [2] 6d a0 [2] 52 bc }

  condition:
    any of them
}