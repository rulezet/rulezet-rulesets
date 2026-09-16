rule TTP_XOR_WriteProcessMemory_c0d5 {
  strings:
    $key_c0d5 = { 97 a7 [2] a5 85 [2] a3 b0 [2] 8d b0 [2] b2 ac }

  condition:
    any of them
}