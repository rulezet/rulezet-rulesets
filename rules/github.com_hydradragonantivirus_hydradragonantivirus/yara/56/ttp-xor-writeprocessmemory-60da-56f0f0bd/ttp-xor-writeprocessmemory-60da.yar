rule TTP_XOR_WriteProcessMemory_60da {
  strings:
    $key_60da = { 37 a8 [2] 05 8a [2] 03 bf [2] 2d bf [2] 12 a3 }

  condition:
    any of them
}