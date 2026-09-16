rule TTP_XOR_WriteProcessMemory_4b00 {
  strings:
    $key_4b00 = { 1c 72 [2] 2e 50 [2] 28 65 [2] 06 65 [2] 39 79 }

  condition:
    any of them
}