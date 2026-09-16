rule TTP_XOR_WriteProcessMemory_3512 {
  strings:
    $key_3512 = { 62 60 [2] 50 42 [2] 56 77 [2] 78 77 [2] 47 6b }

  condition:
    any of them
}