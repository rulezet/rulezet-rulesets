rule TTP_XOR_WriteProcessMemory_1eda {
  strings:
    $key_1eda = { 49 a8 [2] 7b 8a [2] 7d bf [2] 53 bf [2] 6c a3 }

  condition:
    any of them
}