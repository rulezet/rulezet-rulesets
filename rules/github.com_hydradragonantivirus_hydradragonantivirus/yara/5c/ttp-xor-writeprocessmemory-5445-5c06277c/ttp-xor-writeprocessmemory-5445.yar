rule TTP_XOR_WriteProcessMemory_5445 {
  strings:
    $key_5445 = { 03 37 [2] 31 15 [2] 37 20 [2] 19 20 [2] 26 3c }

  condition:
    any of them
}