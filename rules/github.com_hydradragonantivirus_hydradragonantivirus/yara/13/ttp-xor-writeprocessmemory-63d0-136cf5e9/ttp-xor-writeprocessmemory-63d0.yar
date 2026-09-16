rule TTP_XOR_WriteProcessMemory_63d0 {
  strings:
    $key_63d0 = { 34 a2 [2] 06 80 [2] 00 b5 [2] 2e b5 [2] 11 a9 }

  condition:
    any of them
}