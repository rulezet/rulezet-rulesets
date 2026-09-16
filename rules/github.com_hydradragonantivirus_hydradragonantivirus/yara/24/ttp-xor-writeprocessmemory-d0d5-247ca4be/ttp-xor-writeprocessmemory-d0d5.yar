rule TTP_XOR_WriteProcessMemory_d0d5 {
  strings:
    $key_d0d5 = { 87 a7 [2] b5 85 [2] b3 b0 [2] 9d b0 [2] a2 ac }

  condition:
    any of them
}