rule TTP_XOR_WriteProcessMemory_63b5 {
  strings:
    $key_63b5 = { 34 c7 [2] 06 e5 [2] 00 d0 [2] 2e d0 [2] 11 cc }

  condition:
    any of them
}