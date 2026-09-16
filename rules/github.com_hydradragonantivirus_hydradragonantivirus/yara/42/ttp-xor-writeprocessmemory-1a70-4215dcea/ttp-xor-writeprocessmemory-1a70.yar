rule TTP_XOR_WriteProcessMemory_1a70 {
  strings:
    $key_1a70 = { 4d 02 [2] 7f 20 [2] 79 15 [2] 57 15 [2] 68 09 }

  condition:
    any of them
}