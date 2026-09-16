rule TTP_XOR_WriteProcessMemory_efb1 {
  strings:
    $key_efb1 = { b8 c3 [2] 8a e1 [2] 8c d4 [2] a2 d4 [2] 9d c8 }

  condition:
    any of them
}