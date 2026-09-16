rule TTP_XOR_WriteProcessMemory_25da {
  strings:
    $key_25da = { 72 a8 [2] 40 8a [2] 46 bf [2] 68 bf [2] 57 a3 }

  condition:
    any of them
}