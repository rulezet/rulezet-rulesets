rule TTP_XOR_WriteProcessMemory_1372 {
  strings:
    $key_1372 = { 44 00 [2] 76 22 [2] 70 17 [2] 5e 17 [2] 61 0b }

  condition:
    any of them
}