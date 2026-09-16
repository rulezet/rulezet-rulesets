rule TTP_XOR_WriteProcessMemory_73c0 {
  strings:
    $key_73c0 = { 24 b2 [2] 16 90 [2] 10 a5 [2] 3e a5 [2] 01 b9 }

  condition:
    any of them
}