rule TTP_XOR_WriteProcessMemory_7735 {
  strings:
    $key_7735 = { 20 47 [2] 12 65 [2] 14 50 [2] 3a 50 [2] 05 4c }

  condition:
    any of them
}