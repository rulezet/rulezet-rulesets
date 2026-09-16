rule TTP_XOR_WriteProcessMemory_d7c4 {
  strings:
    $key_d7c4 = { 80 b6 [2] b2 94 [2] b4 a1 [2] 9a a1 [2] a5 bd }

  condition:
    any of them
}