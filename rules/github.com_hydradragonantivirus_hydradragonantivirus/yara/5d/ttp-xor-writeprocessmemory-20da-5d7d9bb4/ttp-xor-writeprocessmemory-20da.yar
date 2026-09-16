rule TTP_XOR_WriteProcessMemory_20da {
  strings:
    $key_20da = { 77 a8 [2] 45 8a [2] 43 bf [2] 6d bf [2] 52 a3 }

  condition:
    any of them
}