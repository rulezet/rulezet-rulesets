rule TTP_XOR_WriteProcessMemory_73b3 {
  strings:
    $key_73b3 = { 24 c1 [2] 16 e3 [2] 10 d6 [2] 3e d6 [2] 01 ca }

  condition:
    any of them
}