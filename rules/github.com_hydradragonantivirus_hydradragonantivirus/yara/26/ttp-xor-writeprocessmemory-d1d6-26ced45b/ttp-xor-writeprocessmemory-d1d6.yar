rule TTP_XOR_WriteProcessMemory_d1d6 {
  strings:
    $key_d1d6 = { 86 a4 [2] b4 86 [2] b2 b3 [2] 9c b3 [2] a3 af }

  condition:
    any of them
}