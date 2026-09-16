rule TTP_XOR_WriteProcessMemory_4525 {
  strings:
    $key_4525 = { 12 57 [2] 20 75 [2] 26 40 [2] 08 40 [2] 37 5c }

  condition:
    any of them
}