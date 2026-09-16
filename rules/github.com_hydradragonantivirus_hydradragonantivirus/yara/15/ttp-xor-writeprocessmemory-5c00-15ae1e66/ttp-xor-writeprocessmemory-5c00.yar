rule TTP_XOR_WriteProcessMemory_5c00 {
  strings:
    $key_5c00 = { 0b 72 [2] 39 50 [2] 3f 65 [2] 11 65 [2] 2e 79 }

  condition:
    any of them
}