rule TTP_XOR_WriteProcessMemory_77da {
  strings:
    $key_77da = { 20 a8 [2] 12 8a [2] 14 bf [2] 3a bf [2] 05 a3 }

  condition:
    any of them
}