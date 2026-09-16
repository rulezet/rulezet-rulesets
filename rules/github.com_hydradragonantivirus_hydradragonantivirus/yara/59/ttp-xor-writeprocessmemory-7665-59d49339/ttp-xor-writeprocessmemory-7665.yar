rule TTP_XOR_WriteProcessMemory_7665 {
  strings:
    $key_7665 = { 21 17 [2] 13 35 [2] 15 00 [2] 3b 00 [2] 04 1c }

  condition:
    any of them
}