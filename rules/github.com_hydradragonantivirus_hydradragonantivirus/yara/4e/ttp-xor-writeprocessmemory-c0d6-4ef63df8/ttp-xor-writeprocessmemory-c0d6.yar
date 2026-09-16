rule TTP_XOR_WriteProcessMemory_c0d6 {
  strings:
    $key_c0d6 = { 97 a4 [2] a5 86 [2] a3 b3 [2] 8d b3 [2] b2 af }

  condition:
    any of them
}