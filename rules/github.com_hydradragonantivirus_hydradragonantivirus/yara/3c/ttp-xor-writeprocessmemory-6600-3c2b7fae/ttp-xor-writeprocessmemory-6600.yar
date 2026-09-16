rule TTP_XOR_WriteProcessMemory_6600 {
  strings:
    $key_6600 = { 31 72 [2] 03 50 [2] 05 65 [2] 2b 65 [2] 14 79 }

  condition:
    any of them
}