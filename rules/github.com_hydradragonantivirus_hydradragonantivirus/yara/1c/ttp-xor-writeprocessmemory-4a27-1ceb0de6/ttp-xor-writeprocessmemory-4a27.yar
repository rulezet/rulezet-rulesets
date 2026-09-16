rule TTP_XOR_WriteProcessMemory_4a27 {
  strings:
    $key_4a27 = { 1d 55 [2] 2f 77 [2] 29 42 [2] 07 42 [2] 38 5e }

  condition:
    any of them
}