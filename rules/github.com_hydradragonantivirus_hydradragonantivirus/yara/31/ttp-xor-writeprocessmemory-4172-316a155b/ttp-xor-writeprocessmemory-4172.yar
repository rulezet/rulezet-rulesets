rule TTP_XOR_WriteProcessMemory_4172 {
  strings:
    $key_4172 = { 16 00 [2] 24 22 [2] 22 17 [2] 0c 17 [2] 33 0b }

  condition:
    any of them
}