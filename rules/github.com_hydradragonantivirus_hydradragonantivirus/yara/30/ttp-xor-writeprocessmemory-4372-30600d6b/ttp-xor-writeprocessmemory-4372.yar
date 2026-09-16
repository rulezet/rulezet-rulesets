rule TTP_XOR_WriteProcessMemory_4372 {
  strings:
    $key_4372 = { 14 00 [2] 26 22 [2] 20 17 [2] 0e 17 [2] 31 0b }

  condition:
    any of them
}