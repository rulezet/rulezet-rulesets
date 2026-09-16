rule TTP_XOR_WriteProcessMemory_5c72 {
  strings:
    $key_5c72 = { 0b 00 [2] 39 22 [2] 3f 17 [2] 11 17 [2] 2e 0b }

  condition:
    any of them
}