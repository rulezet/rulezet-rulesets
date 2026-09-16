rule TTP_XOR_WriteProcessMemory_0565 {
  strings:
    $key_0565 = { 52 17 [2] 60 35 [2] 66 00 [2] 48 00 [2] 77 1c }

  condition:
    any of them
}