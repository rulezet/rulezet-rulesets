rule TTP_XOR_WriteProcessMemory_d1c6 {
  strings:
    $key_d1c6 = { 86 b4 [2] b4 96 [2] b2 a3 [2] 9c a3 [2] a3 bf }

  condition:
    any of them
}