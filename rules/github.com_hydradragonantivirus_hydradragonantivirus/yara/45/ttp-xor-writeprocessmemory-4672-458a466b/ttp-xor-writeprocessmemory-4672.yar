rule TTP_XOR_WriteProcessMemory_4672 {
  strings:
    $key_4672 = { 11 00 [2] 23 22 [2] 25 17 [2] 0b 17 [2] 34 0b }

  condition:
    any of them
}