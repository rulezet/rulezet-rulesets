rule TTP_XOR_WriteProcessMemory_6b00 {
  strings:
    $key_6b00 = { 3c 72 [2] 0e 50 [2] 08 65 [2] 26 65 [2] 19 79 }

  condition:
    any of them
}