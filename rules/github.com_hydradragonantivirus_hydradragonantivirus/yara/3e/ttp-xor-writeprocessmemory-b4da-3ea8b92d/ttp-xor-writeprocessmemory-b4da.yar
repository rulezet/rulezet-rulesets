rule TTP_XOR_WriteProcessMemory_b4da {
  strings:
    $key_b4da = { e3 a8 [2] d1 8a [2] d7 bf [2] f9 bf [2] c6 a3 }

  condition:
    any of them
}