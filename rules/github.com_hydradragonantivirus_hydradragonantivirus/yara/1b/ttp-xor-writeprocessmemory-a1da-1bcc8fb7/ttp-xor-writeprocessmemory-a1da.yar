rule TTP_XOR_WriteProcessMemory_a1da {
  strings:
    $key_a1da = { f6 a8 [2] c4 8a [2] c2 bf [2] ec bf [2] d3 a3 }

  condition:
    any of them
}