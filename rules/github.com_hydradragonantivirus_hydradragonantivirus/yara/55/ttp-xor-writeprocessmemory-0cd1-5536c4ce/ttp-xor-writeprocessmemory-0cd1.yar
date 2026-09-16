rule TTP_XOR_WriteProcessMemory_0cd1 {
  strings:
    $key_0cd1 = { 5b a3 [2] 69 81 [2] 6f b4 [2] 41 b4 [2] 7e a8 }

  condition:
    any of them
}