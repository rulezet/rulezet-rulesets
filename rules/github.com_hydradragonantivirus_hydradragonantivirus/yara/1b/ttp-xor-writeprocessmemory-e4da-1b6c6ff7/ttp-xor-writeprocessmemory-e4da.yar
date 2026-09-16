rule TTP_XOR_WriteProcessMemory_e4da {
  strings:
    $key_e4da = { b3 a8 [2] 81 8a [2] 87 bf [2] a9 bf [2] 96 a3 }

  condition:
    any of them
}