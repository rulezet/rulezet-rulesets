rule TTP_XOR_WriteProcessMemory_3eda {
  strings:
    $key_3eda = { 69 a8 [2] 5b 8a [2] 5d bf [2] 73 bf [2] 4c a3 }

  condition:
    any of them
}