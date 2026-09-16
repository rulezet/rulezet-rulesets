rule TTP_XOR_WriteProcessMemory_6172 {
  strings:
    $key_6172 = { 36 00 [2] 04 22 [2] 02 17 [2] 2c 17 [2] 13 0b }

  condition:
    any of them
}