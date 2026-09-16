rule TTP_XOR_WriteProcessMemory_6351 {
  strings:
    $key_6351 = { 34 23 [2] 06 01 [2] 00 34 [2] 2e 34 [2] 11 28 }

  condition:
    any of them
}