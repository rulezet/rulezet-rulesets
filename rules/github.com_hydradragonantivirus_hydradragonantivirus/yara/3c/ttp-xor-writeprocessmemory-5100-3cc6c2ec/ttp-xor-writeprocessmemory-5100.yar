rule TTP_XOR_WriteProcessMemory_5100 {
  strings:
    $key_5100 = { 06 72 [2] 34 50 [2] 32 65 [2] 1c 65 [2] 23 79 }

  condition:
    any of them
}