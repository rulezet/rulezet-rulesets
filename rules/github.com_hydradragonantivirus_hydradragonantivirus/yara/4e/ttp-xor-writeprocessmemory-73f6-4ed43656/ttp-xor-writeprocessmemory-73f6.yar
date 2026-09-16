rule TTP_XOR_WriteProcessMemory_73f6 {
  strings:
    $key_73f6 = { 24 84 [2] 16 a6 [2] 10 93 [2] 3e 93 [2] 01 8f }

  condition:
    any of them
}