rule TTP_XOR_WriteProcessMemory_efb4 {
  strings:
    $key_efb4 = { b8 c6 [2] 8a e4 [2] 8c d1 [2] a2 d1 [2] 9d cd }

  condition:
    any of them
}