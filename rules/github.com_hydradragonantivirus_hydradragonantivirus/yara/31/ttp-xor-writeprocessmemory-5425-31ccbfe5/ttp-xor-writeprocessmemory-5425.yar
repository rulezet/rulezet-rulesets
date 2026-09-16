rule TTP_XOR_WriteProcessMemory_5425 {
  strings:
    $key_5425 = { 03 57 [2] 31 75 [2] 37 40 [2] 19 40 [2] 26 5c }

  condition:
    any of them
}