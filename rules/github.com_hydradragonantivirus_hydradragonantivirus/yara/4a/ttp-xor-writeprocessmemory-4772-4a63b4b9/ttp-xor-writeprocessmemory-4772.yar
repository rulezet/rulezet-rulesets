rule TTP_XOR_WriteProcessMemory_4772 {
  strings:
    $key_4772 = { 10 00 [2] 22 22 [2] 24 17 [2] 0a 17 [2] 35 0b }

  condition:
    any of them
}