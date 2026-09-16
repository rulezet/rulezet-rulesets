rule TTP_XOR_WriteProcessMemory_33b0 {
  strings:
    $key_33b0 = { 64 c2 [2] 56 e0 [2] 50 d5 [2] 7e d5 [2] 41 c9 }

  condition:
    any of them
}