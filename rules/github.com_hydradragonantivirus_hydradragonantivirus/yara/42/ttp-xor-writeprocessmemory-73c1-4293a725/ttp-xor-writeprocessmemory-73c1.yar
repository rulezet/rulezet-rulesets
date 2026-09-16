rule TTP_XOR_WriteProcessMemory_73c1 {
  strings:
    $key_73c1 = { 24 b3 [2] 16 91 [2] 10 a4 [2] 3e a4 [2] 01 b8 }

  condition:
    any of them
}