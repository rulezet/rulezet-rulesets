rule TTP_XOR_WriteProcessMemory_7912 {
  strings:
    $key_7912 = { 2e 60 [2] 1c 42 [2] 1a 77 [2] 34 77 [2] 0b 6b }

  condition:
    any of them
}