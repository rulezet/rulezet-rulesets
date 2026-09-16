rule TTP_XOR_WriteProcessMemory_41c5 {
  strings:
    $key_41c5 = { 16 b7 [2] 24 95 [2] 22 a0 [2] 0c a0 [2] 33 bc }

  condition:
    any of them
}