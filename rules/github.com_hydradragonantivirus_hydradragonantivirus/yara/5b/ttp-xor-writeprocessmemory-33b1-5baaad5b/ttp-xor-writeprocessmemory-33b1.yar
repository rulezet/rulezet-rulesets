rule TTP_XOR_WriteProcessMemory_33b1 {
  strings:
    $key_33b1 = { 64 c3 [2] 56 e1 [2] 50 d4 [2] 7e d4 [2] 41 c8 }

  condition:
    any of them
}