rule TTP_XOR_WriteProcessMemory_5eda {
  strings:
    $key_5eda = { 09 a8 [2] 3b 8a [2] 3d bf [2] 13 bf [2] 2c a3 }

  condition:
    any of them
}