rule TTP_XOR_WriteProcessMemory_41c0 {
  strings:
    $key_41c0 = { 16 b2 [2] 24 90 [2] 22 a5 [2] 0c a5 [2] 33 b9 }

  condition:
    any of them
}