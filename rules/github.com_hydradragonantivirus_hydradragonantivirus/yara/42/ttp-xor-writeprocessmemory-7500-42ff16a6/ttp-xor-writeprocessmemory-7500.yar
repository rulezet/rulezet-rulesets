rule TTP_XOR_WriteProcessMemory_7500 {
  strings:
    $key_7500 = { 22 72 [2] 10 50 [2] 16 65 [2] 38 65 [2] 07 79 }

  condition:
    any of them
}