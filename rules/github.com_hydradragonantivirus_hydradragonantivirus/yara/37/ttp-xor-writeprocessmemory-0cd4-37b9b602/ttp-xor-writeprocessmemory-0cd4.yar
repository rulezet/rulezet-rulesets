rule TTP_XOR_WriteProcessMemory_0cd4 {
  strings:
    $key_0cd4 = { 5b a6 [2] 69 84 [2] 6f b1 [2] 41 b1 [2] 7e ad }

  condition:
    any of them
}