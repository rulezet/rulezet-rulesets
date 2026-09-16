rule TTP_XOR_WriteProcessMemory_1d65 {
  strings:
    $key_1d65 = { 4a 17 [2] 78 35 [2] 7e 00 [2] 50 00 [2] 6f 1c }

  condition:
    any of them
}