rule TTP_XOR_WriteProcessMemory_6425 {
  strings:
    $key_6425 = { 33 57 [2] 01 75 [2] 07 40 [2] 29 40 [2] 16 5c }

  condition:
    any of them
}