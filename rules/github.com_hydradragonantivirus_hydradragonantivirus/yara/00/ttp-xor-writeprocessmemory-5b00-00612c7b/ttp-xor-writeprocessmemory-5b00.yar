rule TTP_XOR_WriteProcessMemory_5b00 {
  strings:
    $key_5b00 = { 0c 72 [2] 3e 50 [2] 38 65 [2] 16 65 [2] 29 79 }

  condition:
    any of them
}