rule TTP_XOR_WriteProcessMemory_c2c7 {
  strings:
    $key_c2c7 = { 95 b5 [2] a7 97 [2] a1 a2 [2] 8f a2 [2] b0 be }

  condition:
    any of them
}