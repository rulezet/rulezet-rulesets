rule TTP_XOR_WriteProcessMemory_6427 {
  strings:
    $key_6427 = { 33 55 [2] 01 77 [2] 07 42 [2] 29 42 [2] 16 5e }

  condition:
    any of them
}