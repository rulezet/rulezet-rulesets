rule TTP_XOR_WriteProcessMemory_7773 {
  strings:
    $key_7773 = { 20 01 [2] 12 23 [2] 14 16 [2] 3a 16 [2] 05 0a }

  condition:
    any of them
}