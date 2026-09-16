rule TTP_XOR_WriteProcessMemory_2512 {
  strings:
    $key_2512 = { 72 60 [2] 40 42 [2] 46 77 [2] 68 77 [2] 57 6b }

  condition:
    any of them
}