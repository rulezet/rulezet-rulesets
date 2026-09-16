rule TTP_XOR_WriteProcessMemory_c5c6 {
  strings:
    $key_c5c6 = { 92 b4 [2] a0 96 [2] a6 a3 [2] 88 a3 [2] b7 bf }

  condition:
    any of them
}