rule TTP_XOR_WriteProcessMemory_3772 {
  strings:
    $key_3772 = { 60 00 [2] 52 22 [2] 54 17 [2] 7a 17 [2] 45 0b }

  condition:
    any of them
}