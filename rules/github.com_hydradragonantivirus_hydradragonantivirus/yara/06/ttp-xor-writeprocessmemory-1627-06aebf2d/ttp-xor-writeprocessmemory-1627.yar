rule TTP_XOR_WriteProcessMemory_1627 {
  strings:
    $key_1627 = { 41 55 [2] 73 77 [2] 75 42 [2] 5b 42 [2] 64 5e }

  condition:
    any of them
}