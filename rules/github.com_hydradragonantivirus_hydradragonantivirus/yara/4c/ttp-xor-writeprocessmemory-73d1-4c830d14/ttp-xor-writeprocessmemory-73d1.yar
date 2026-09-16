rule TTP_XOR_WriteProcessMemory_73d1 {
  strings:
    $key_73d1 = { 24 a3 [2] 16 81 [2] 10 b4 [2] 3e b4 [2] 01 a8 }

  condition:
    any of them
}