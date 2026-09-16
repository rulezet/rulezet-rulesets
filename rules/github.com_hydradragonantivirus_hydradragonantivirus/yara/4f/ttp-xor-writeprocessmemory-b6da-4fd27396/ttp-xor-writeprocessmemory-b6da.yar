rule TTP_XOR_WriteProcessMemory_b6da {
  strings:
    $key_b6da = { e1 a8 [2] d3 8a [2] d5 bf [2] fb bf [2] c4 a3 }

  condition:
    any of them
}