rule TTP_XOR_WriteProcessMemory_a6c6 {
  strings:
    $key_a6c6 = { f1 b4 [2] c3 96 [2] c5 a3 [2] eb a3 [2] d4 bf }

  condition:
    any of them
}