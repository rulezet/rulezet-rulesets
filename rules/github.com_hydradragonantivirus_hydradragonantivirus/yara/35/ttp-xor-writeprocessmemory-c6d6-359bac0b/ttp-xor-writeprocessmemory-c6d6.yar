rule TTP_XOR_WriteProcessMemory_c6d6 {
  strings:
    $key_c6d6 = { 91 a4 [2] a3 86 [2] a5 b3 [2] 8b b3 [2] b4 af }

  condition:
    any of them
}