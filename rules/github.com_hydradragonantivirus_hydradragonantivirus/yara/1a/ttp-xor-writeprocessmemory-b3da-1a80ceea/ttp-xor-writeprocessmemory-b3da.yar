rule TTP_XOR_WriteProcessMemory_b3da {
  strings:
    $key_b3da = { e4 a8 [2] d6 8a [2] d0 bf [2] fe bf [2] c1 a3 }

  condition:
    any of them
}