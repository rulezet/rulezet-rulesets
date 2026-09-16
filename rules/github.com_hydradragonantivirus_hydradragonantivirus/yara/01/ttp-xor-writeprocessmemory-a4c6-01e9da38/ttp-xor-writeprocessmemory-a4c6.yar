rule TTP_XOR_WriteProcessMemory_a4c6 {
  strings:
    $key_a4c6 = { f3 b4 [2] c1 96 [2] c7 a3 [2] e9 a3 [2] d6 bf }

  condition:
    any of them
}