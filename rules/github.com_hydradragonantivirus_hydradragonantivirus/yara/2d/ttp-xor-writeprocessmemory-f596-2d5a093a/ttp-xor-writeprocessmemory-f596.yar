rule TTP_XOR_WriteProcessMemory_f596 {
  strings:
    $key_f596 = { a2 e4 [2] 90 c6 [2] 96 f3 [2] b8 f3 [2] 87 ef }

  condition:
    any of them
}