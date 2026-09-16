rule TTP_XOR_WriteProcessMemory_b1da {
  strings:
    $key_b1da = { e6 a8 [2] d4 8a [2] d2 bf [2] fc bf [2] c3 a3 }

  condition:
    any of them
}