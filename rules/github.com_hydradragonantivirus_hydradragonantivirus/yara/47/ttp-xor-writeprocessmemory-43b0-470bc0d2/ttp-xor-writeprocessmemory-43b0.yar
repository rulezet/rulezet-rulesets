rule TTP_XOR_WriteProcessMemory_43b0 {
  strings:
    $key_43b0 = { 14 c2 [2] 26 e0 [2] 20 d5 [2] 0e d5 [2] 31 c9 }

  condition:
    any of them
}