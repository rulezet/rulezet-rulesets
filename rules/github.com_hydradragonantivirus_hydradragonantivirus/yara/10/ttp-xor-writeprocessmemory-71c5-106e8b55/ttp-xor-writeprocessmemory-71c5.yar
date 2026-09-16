rule TTP_XOR_WriteProcessMemory_71c5 {
  strings:
    $key_71c5 = { 26 b7 [2] 14 95 [2] 12 a0 [2] 3c a0 [2] 03 bc }

  condition:
    any of them
}