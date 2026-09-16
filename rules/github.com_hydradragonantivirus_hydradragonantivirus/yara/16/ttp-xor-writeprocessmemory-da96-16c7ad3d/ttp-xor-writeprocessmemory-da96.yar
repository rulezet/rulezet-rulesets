rule TTP_XOR_WriteProcessMemory_da96 {
  strings:
    $key_da96 = { 8d e4 [2] bf c6 [2] b9 f3 [2] 97 f3 [2] a8 ef }

  condition:
    any of them
}