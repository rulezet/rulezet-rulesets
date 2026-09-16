rule TTP_XOR_WriteProcessMemory_a2da {
  strings:
    $key_a2da = { f5 a8 [2] c7 8a [2] c1 bf [2] ef bf [2] d0 a3 }

  condition:
    any of them
}