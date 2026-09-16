rule TTP_XOR_WriteProcessMemory_a7c6 {
  strings:
    $key_a7c6 = { f0 b4 [2] c2 96 [2] c4 a3 [2] ea a3 [2] d5 bf }

  condition:
    any of them
}