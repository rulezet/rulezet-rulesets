rule TTP_XOR_WriteProcessMemory_4572 {
  strings:
    $key_4572 = { 12 00 [2] 20 22 [2] 26 17 [2] 08 17 [2] 37 0b }

  condition:
    any of them
}