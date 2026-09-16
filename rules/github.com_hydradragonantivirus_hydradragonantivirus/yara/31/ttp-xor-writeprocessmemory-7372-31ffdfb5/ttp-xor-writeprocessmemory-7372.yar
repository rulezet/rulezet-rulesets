rule TTP_XOR_WriteProcessMemory_7372 {
  strings:
    $key_7372 = { 24 00 [2] 16 22 [2] 10 17 [2] 3e 17 [2] 01 0b }

  condition:
    any of them
}