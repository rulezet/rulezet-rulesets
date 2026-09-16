rule TTP_XOR_WriteProcessMemory_6063 {
  strings:
    $key_6063 = { 37 11 [2] 05 33 [2] 03 06 [2] 2d 06 [2] 12 1a }

  condition:
    any of them
}