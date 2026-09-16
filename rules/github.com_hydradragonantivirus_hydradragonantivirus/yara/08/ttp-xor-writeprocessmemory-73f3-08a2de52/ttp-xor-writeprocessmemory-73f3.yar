rule TTP_XOR_WriteProcessMemory_73f3 {
  strings:
    $key_73f3 = { 24 81 [2] 16 a3 [2] 10 96 [2] 3e 96 [2] 01 8a }

  condition:
    any of them
}