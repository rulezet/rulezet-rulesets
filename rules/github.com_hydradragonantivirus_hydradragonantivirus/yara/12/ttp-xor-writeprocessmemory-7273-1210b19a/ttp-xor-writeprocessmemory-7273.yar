rule TTP_XOR_WriteProcessMemory_7273 {
  strings:
    $key_7273 = { 25 01 [2] 17 23 [2] 11 16 [2] 3f 16 [2] 00 0a }

  condition:
    any of them
}