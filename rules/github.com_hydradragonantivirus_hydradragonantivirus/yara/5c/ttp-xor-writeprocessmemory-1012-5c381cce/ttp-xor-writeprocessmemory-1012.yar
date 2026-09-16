rule TTP_XOR_WriteProcessMemory_1012 {
  strings:
    $key_1012 = { 47 60 [2] 75 42 [2] 73 77 [2] 5d 77 [2] 62 6b }

  condition:
    any of them
}