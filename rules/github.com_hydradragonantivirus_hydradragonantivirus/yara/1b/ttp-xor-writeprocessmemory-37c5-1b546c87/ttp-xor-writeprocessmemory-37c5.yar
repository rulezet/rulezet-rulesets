rule TTP_XOR_WriteProcessMemory_37c5 {
  strings:
    $key_37c5 = { 60 b7 [2] 52 95 [2] 54 a0 [2] 7a a0 [2] 45 bc }

  condition:
    any of them
}