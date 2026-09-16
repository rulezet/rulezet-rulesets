rule TTP_XOR_WriteProcessMemory_4e27 {
  strings:
    $key_4e27 = { 19 55 [2] 2b 77 [2] 2d 42 [2] 03 42 [2] 3c 5e }

  condition:
    any of them
}