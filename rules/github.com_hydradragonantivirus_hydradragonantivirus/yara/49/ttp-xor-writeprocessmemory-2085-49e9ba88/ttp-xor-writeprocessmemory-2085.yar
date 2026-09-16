rule TTP_XOR_WriteProcessMemory_2085 {
  strings:
    $key_2085 = { 77 f7 [2] 45 d5 [2] 43 e0 [2] 6d e0 [2] 52 fc }

  condition:
    any of them
}