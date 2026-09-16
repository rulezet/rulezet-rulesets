rule TTP_XOR_WriteProcessMemory_d1c4 {
  strings:
    $key_d1c4 = { 86 b6 [2] b4 94 [2] b2 a1 [2] 9c a1 [2] a3 bd }

  condition:
    any of them
}