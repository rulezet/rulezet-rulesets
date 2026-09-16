rule TTP_XOR_WriteProcessMemory_4425 {
  strings:
    $key_4425 = { 13 57 [2] 21 75 [2] 27 40 [2] 09 40 [2] 36 5c }

  condition:
    any of them
}