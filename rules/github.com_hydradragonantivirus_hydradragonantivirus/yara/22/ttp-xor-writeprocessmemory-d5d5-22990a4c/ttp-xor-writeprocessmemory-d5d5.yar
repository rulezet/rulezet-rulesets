rule TTP_XOR_WriteProcessMemory_d5d5 {
  strings:
    $key_d5d5 = { 82 a7 [2] b0 85 [2] b6 b0 [2] 98 b0 [2] a7 ac }

  condition:
    any of them
}