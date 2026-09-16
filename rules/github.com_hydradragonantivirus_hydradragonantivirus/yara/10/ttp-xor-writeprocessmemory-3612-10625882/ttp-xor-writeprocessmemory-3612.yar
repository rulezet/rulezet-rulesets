rule TTP_XOR_WriteProcessMemory_3612 {
  strings:
    $key_3612 = { 61 60 [2] 53 42 [2] 55 77 [2] 7b 77 [2] 44 6b }

  condition:
    any of them
}