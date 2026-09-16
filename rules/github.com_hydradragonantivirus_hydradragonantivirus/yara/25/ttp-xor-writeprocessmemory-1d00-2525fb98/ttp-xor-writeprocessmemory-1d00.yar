rule TTP_XOR_WriteProcessMemory_1d00 {
  strings:
    $key_1d00 = { 4a 72 [2] 78 50 [2] 7e 65 [2] 50 65 [2] 6f 79 }

  condition:
    any of them
}