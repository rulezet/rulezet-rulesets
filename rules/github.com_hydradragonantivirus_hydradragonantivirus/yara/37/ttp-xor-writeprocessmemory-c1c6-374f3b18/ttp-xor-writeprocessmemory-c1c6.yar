rule TTP_XOR_WriteProcessMemory_c1c6 {
  strings:
    $key_c1c6 = { 96 b4 [2] a4 96 [2] a2 a3 [2] 8c a3 [2] b3 bf }

  condition:
    any of them
}