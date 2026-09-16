rule TTP_XOR_WriteProcessMemory_dbd6 {
  strings:
    $key_dbd6 = { 8c a4 [2] be 86 [2] b8 b3 [2] 96 b3 [2] a9 af }

  condition:
    any of them
}