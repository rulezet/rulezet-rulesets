rule TTP_XOR_WriteProcessMemory_c3c6 {
  strings:
    $key_c3c6 = { 94 b4 [2] a6 96 [2] a0 a3 [2] 8e a3 [2] b1 bf }

  condition:
    any of them
}