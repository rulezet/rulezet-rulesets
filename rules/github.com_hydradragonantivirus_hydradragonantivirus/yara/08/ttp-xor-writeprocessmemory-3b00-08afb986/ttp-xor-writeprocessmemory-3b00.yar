rule TTP_XOR_WriteProcessMemory_3b00 {
  strings:
    $key_3b00 = { 6c 72 [2] 5e 50 [2] 58 65 [2] 76 65 [2] 49 79 }

  condition:
    any of them
}