rule TTP_XOR_WriteProcessMemory_2746 {
  strings:
    $key_2746 = { 70 34 [2] 42 16 [2] 44 23 [2] 6a 23 [2] 55 3f }

  condition:
    any of them
}