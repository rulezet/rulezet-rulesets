rule TTP_XOR_WriteProcessMemory_e280 {
  strings:
    $key_e280 = { b5 f2 [2] 87 d0 [2] 81 e5 [2] af e5 [2] 90 f9 }

  condition:
    any of them
}