rule TTP_XOR_WriteProcessMemory_da90 {
  strings:
    $key_da90 = { 8d e2 [2] bf c0 [2] b9 f5 [2] 97 f5 [2] a8 e9 }

  condition:
    any of them
}