rule TTP_XOR_WriteProcessMemory_30da {
  strings:
    $key_30da = { 67 a8 [2] 55 8a [2] 53 bf [2] 7d bf [2] 42 a3 }

  condition:
    any of them
}