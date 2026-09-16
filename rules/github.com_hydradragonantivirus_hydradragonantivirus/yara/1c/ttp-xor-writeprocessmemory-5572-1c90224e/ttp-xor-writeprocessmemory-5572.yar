rule TTP_XOR_WriteProcessMemory_5572 {
  strings:
    $key_5572 = { 02 00 [2] 30 22 [2] 36 17 [2] 18 17 [2] 27 0b }

  condition:
    any of them
}