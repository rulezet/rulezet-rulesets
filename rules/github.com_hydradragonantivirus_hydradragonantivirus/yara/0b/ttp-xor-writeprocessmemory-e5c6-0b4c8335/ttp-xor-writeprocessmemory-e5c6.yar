rule TTP_XOR_WriteProcessMemory_e5c6 {
  strings:
    $key_e5c6 = { b2 b4 [2] 80 96 [2] 86 a3 [2] a8 a3 [2] 97 bf }

  condition:
    any of them
}