rule TTP_XOR_WriteProcessMemory_5665 {
  strings:
    $key_5665 = { 01 17 [2] 33 35 [2] 35 00 [2] 1b 00 [2] 24 1c }

  condition:
    any of them
}