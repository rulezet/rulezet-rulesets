rule TTP_XOR_WriteProcessMemory_04da {
  strings:
    $key_04da = { 53 a8 [2] 61 8a [2] 67 bf [2] 49 bf [2] 76 a3 }

  condition:
    any of them
}