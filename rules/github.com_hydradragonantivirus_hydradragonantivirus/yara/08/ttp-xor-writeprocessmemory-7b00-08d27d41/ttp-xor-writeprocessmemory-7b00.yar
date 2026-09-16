rule TTP_XOR_WriteProcessMemory_7b00 {
  strings:
    $key_7b00 = { 2c 72 [2] 1e 50 [2] 18 65 [2] 36 65 [2] 09 79 }

  condition:
    any of them
}