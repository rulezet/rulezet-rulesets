rule TTP_XOR_WriteProcessMemory_da92 {
  strings:
    $key_da92 = { 8d e0 [2] bf c2 [2] b9 f7 [2] 97 f7 [2] a8 eb }

  condition:
    any of them
}