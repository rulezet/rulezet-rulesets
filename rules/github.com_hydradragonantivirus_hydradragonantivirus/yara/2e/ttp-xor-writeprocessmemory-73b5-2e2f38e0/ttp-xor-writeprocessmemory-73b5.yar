rule TTP_XOR_WriteProcessMemory_73b5 {
  strings:
    $key_73b5 = { 24 c7 [2] 16 e5 [2] 10 d0 [2] 3e d0 [2] 01 cc }

  condition:
    any of them
}