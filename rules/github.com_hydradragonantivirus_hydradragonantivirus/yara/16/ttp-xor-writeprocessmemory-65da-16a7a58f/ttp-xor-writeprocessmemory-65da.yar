rule TTP_XOR_WriteProcessMemory_65da {
  strings:
    $key_65da = { 32 a8 [2] 00 8a [2] 06 bf [2] 28 bf [2] 17 a3 }

  condition:
    any of them
}