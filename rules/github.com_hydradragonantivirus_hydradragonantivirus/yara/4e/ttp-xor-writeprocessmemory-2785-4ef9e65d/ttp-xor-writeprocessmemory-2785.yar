rule TTP_XOR_WriteProcessMemory_2785 {
  strings:
    $key_2785 = { 70 f7 [2] 42 d5 [2] 44 e0 [2] 6a e0 [2] 55 fc }

  condition:
    any of them
}