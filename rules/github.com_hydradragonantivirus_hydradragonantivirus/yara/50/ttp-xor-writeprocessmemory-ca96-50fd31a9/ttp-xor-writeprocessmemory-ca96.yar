rule TTP_XOR_WriteProcessMemory_ca96 {
  strings:
    $key_ca96 = { 9d e4 [2] af c6 [2] a9 f3 [2] 87 f3 [2] b8 ef }

  condition:
    any of them
}