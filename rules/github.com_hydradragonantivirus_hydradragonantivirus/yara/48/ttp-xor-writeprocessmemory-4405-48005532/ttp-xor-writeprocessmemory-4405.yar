rule TTP_XOR_WriteProcessMemory_4405 {
  strings:
    $key_4405 = { 13 77 [2] 21 55 [2] 27 60 [2] 09 60 [2] 36 7c }

  condition:
    any of them
}