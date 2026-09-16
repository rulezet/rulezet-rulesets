rule TTP_XOR_WriteProcessMemory_5500 {
  strings:
    $key_5500 = { 02 72 [2] 30 50 [2] 36 65 [2] 18 65 [2] 27 79 }

  condition:
    any of them
}