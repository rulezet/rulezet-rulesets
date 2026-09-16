rule TTP_XOR_WriteProcessMemory_c7c6 {
  strings:
    $key_c7c6 = { 90 b4 [2] a2 96 [2] a4 a3 [2] 8a a3 [2] b5 bf }

  condition:
    any of them
}