rule TTP_XOR_WriteProcessMemory_4150 {
  strings:
    $key_4150 = { 16 22 [2] 24 00 [2] 22 35 [2] 0c 35 [2] 33 29 }

  condition:
    any of them
}