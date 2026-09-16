rule TTP_XOR_WriteProcessMemory_4427 {
  strings:
    $key_4427 = { 13 55 [2] 21 77 [2] 27 42 [2] 09 42 [2] 36 5e }

  condition:
    any of them
}