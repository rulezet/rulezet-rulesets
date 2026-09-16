rule TTP_XOR_WriteProcessMemory_4400 {
  strings:
    $key_4400 = { 13 72 [2] 21 50 [2] 27 65 [2] 09 65 [2] 36 79 }

  condition:
    any of them
}