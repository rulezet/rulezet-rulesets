rule TTP_XOR_WriteProcessMemory_6305 {
  strings:
    $key_6305 = { 34 77 [2] 06 55 [2] 00 60 [2] 2e 60 [2] 11 7c }

  condition:
    any of them
}