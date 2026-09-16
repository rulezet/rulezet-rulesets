rule TTP_XOR_WriteProcessMemory_e8b1 {
  strings:
    $key_e8b1 = { bf c3 [2] 8d e1 [2] 8b d4 [2] a5 d4 [2] 9a c8 }

  condition:
    any of them
}