rule TTP_XOR_WriteProcessMemory_1d72 {
  strings:
    $key_1d72 = { 4a 00 [2] 78 22 [2] 7e 17 [2] 50 17 [2] 6f 0b }

  condition:
    any of them
}