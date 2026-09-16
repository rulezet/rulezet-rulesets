rule TTP_XOR_WriteProcessMemory_42d0 {
  strings:
    $key_42d0 = { 15 a2 [2] 27 80 [2] 21 b5 [2] 0f b5 [2] 30 a9 }

  condition:
    any of them
}