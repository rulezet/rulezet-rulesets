rule TTP_XOR_WriteProcessMemory_c1d5 {
  strings:
    $key_c1d5 = { 96 a7 [2] a4 85 [2] a2 b0 [2] 8c b0 [2] b3 ac }

  condition:
    any of them
}