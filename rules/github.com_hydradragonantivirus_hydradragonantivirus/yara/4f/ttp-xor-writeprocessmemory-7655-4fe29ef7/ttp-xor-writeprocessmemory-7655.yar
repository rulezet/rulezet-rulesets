rule TTP_XOR_WriteProcessMemory_7655 {
  strings:
    $key_7655 = { 21 27 [2] 13 05 [2] 15 30 [2] 3b 30 [2] 04 2c }

  condition:
    any of them
}