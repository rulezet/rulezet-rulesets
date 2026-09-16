rule TTP_XOR_WriteProcessMemory_1172 {
  strings:
    $key_1172 = { 46 00 [2] 74 22 [2] 72 17 [2] 5c 17 [2] 63 0b }

  condition:
    any of them
}