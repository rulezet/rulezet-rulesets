rule TTP_XOR_WriteProcessMemory_6571 {
  strings:
    $key_6571 = { 32 03 [2] 00 21 [2] 06 14 [2] 28 14 [2] 17 08 }

  condition:
    any of them
}