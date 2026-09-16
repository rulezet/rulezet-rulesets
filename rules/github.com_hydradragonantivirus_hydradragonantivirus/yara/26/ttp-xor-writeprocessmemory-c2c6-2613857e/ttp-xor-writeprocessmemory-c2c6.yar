rule TTP_XOR_WriteProcessMemory_c2c6 {
  strings:
    $key_c2c6 = { 95 b4 [2] a7 96 [2] a1 a3 [2] 8f a3 [2] b0 bf }

  condition:
    any of them
}