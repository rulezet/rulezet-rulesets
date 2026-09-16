rule TTP_XOR_WriteProcessMemory_a5c6 {
  strings:
    $key_a5c6 = { f2 b4 [2] c0 96 [2] c6 a3 [2] e8 a3 [2] d7 bf }

  condition:
    any of them
}