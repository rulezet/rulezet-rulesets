rule TTP_XOR_WriteProcessMemory_12c5 {
  strings:
    $key_12c5 = { 45 b7 [2] 77 95 [2] 71 a0 [2] 5f a0 [2] 60 bc }

  condition:
    any of them
}