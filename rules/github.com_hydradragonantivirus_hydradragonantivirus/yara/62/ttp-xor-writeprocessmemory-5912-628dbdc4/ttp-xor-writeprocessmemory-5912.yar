rule TTP_XOR_WriteProcessMemory_5912 {
  strings:
    $key_5912 = { 0e 60 [2] 3c 42 [2] 3a 77 [2] 14 77 [2] 2b 6b }

  condition:
    any of them
}