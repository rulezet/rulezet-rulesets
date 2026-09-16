rule TTP_XOR_WriteProcessMemory_6eda {
  strings:
    $key_6eda = { 39 a8 [2] 0b 8a [2] 0d bf [2] 23 bf [2] 1c a3 }

  condition:
    any of them
}