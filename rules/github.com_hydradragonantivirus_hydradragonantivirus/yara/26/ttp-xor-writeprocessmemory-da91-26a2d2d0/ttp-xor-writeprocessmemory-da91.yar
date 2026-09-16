rule TTP_XOR_WriteProcessMemory_da91 {
  strings:
    $key_da91 = { 8d e3 [2] bf c1 [2] b9 f4 [2] 97 f4 [2] a8 e8 }

  condition:
    any of them
}