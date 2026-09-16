rule TTP_XOR_WriteProcessMemory_02da {
  strings:
    $key_02da = { 55 a8 [2] 67 8a [2] 61 bf [2] 4f bf [2] 70 a3 }

  condition:
    any of them
}