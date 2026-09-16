rule TTP_XOR_WriteProcessMemory_4812 {
  strings:
    $key_4812 = { 1f 60 [2] 2d 42 [2] 2b 77 [2] 05 77 [2] 3a 6b }

  condition:
    any of them
}