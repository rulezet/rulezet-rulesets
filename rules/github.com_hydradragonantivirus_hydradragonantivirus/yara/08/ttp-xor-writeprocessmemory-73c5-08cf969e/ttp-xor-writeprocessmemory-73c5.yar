rule TTP_XOR_WriteProcessMemory_73c5 {
  strings:
    $key_73c5 = { 24 b7 [2] 16 95 [2] 10 a0 [2] 3e a0 [2] 01 bc }

  condition:
    any of them
}