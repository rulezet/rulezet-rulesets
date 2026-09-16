rule TTP_XOR_WriteProcessMemory_d7d5 {
  strings:
    $key_d7d5 = { 80 a7 [2] b2 85 [2] b4 b0 [2] 9a b0 [2] a5 ac }

  condition:
    any of them
}