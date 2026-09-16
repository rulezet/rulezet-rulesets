rule TTP_XOR_WriteProcessMemory_b4c6 {
  strings:
    $key_b4c6 = { e3 b4 [2] d1 96 [2] d7 a3 [2] f9 a3 [2] c6 bf }

  condition:
    any of them
}