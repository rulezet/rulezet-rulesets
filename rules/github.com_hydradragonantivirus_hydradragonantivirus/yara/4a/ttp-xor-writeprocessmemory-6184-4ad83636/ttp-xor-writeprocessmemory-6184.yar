rule TTP_XOR_WriteProcessMemory_6184 {
  strings:
    $key_6184 = { 36 f6 [2] 04 d4 [2] 02 e1 [2] 2c e1 [2] 13 fd }

  condition:
    any of them
}