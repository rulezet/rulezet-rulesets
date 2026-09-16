rule TTP_XOR_WriteProcessMemory_1a27 {
  strings:
    $key_1a27 = { 4d 55 [2] 7f 77 [2] 79 42 [2] 57 42 [2] 68 5e }

  condition:
    any of them
}