rule TTP_XOR_WriteProcessMemory_4300 {
  strings:
    $key_4300 = { 14 72 [2] 26 50 [2] 20 65 [2] 0e 65 [2] 31 79 }

  condition:
    any of them
}