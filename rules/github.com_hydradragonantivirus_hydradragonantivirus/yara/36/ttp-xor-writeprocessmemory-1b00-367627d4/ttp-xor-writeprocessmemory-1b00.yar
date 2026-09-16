rule TTP_XOR_WriteProcessMemory_1b00 {
  strings:
    $key_1b00 = { 4c 72 [2] 7e 50 [2] 78 65 [2] 56 65 [2] 69 79 }

  condition:
    any of them
}