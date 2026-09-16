rule TTP_XOR_WriteProcessMemory_d284 {
  strings:
    $key_d284 = { 85 f6 [2] b7 d4 [2] b1 e1 [2] 9f e1 [2] a0 fd }

  condition:
    any of them
}