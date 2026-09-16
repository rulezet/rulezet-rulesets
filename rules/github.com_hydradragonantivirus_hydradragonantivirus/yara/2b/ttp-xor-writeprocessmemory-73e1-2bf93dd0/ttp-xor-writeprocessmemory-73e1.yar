rule TTP_XOR_WriteProcessMemory_73e1 {
  strings:
    $key_73e1 = { 24 93 [2] 16 b1 [2] 10 84 [2] 3e 84 [2] 01 98 }

  condition:
    any of them
}