rule TTP_XOR_WriteProcessMemory_5727 {
  strings:
    $key_5727 = { 00 55 [2] 32 77 [2] 34 42 [2] 1a 42 [2] 25 5e }

  condition:
    any of them
}