rule TTP_XOR_WriteProcessMemory_5f27 {
  strings:
    $key_5f27 = { 08 55 [2] 3a 77 [2] 3c 42 [2] 12 42 [2] 2d 5e }

  condition:
    any of them
}