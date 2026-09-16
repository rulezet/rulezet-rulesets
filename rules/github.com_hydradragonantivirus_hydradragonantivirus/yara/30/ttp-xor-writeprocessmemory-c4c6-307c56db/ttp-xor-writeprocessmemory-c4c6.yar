rule TTP_XOR_WriteProcessMemory_c4c6 {
  strings:
    $key_c4c6 = { 93 b4 [2] a1 96 [2] a7 a3 [2] 89 a3 [2] b6 bf }

  condition:
    any of them
}