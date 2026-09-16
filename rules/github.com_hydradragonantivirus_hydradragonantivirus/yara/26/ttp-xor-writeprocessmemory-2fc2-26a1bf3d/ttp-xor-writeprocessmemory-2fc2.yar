rule TTP_XOR_WriteProcessMemory_2fc2 {
  strings:
    $key_2fc2 = { 78 b0 [2] 4a 92 [2] 4c a7 [2] 62 a7 [2] 5d bb }

  condition:
    any of them
}