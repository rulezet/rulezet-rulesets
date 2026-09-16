rule TTP_XOR_WriteProcessMemory_4600 {
  strings:
    $key_4600 = { 11 72 [2] 23 50 [2] 25 65 [2] 0b 65 [2] 34 79 }

  condition:
    any of them
}