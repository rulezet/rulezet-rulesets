rule TTP_XOR_WriteProcessMemory_6700 {
  strings:
    $key_6700 = { 30 72 [2] 02 50 [2] 04 65 [2] 2a 65 [2] 15 79 }

  condition:
    any of them
}