rule TTP_XOR_WriteProcessMemory_6812 {
  strings:
    $key_6812 = { 3f 60 [2] 0d 42 [2] 0b 77 [2] 25 77 [2] 1a 6b }

  condition:
    any of them
}