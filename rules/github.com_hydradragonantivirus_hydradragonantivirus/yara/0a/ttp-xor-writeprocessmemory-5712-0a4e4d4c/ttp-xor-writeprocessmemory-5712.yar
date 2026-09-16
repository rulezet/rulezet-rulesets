rule TTP_XOR_WriteProcessMemory_5712 {
  strings:
    $key_5712 = { 00 60 [2] 32 42 [2] 34 77 [2] 1a 77 [2] 25 6b }

  condition:
    any of them
}