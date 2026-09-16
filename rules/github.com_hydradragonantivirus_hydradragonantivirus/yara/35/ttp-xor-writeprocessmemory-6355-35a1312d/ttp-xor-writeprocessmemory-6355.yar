rule TTP_XOR_WriteProcessMemory_6355 {
  strings:
    $key_6355 = { 34 27 [2] 06 05 [2] 00 30 [2] 2e 30 [2] 11 2c }

  condition:
    any of them
}