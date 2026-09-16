rule TTP_XOR_WriteProcessMemory_22d1 {
  strings:
    $key_22d1 = { 75 a3 [2] 47 81 [2] 41 b4 [2] 6f b4 [2] 50 a8 }

  condition:
    any of them
}