rule TTP_XOR_WriteProcessMemory_79da {
  strings:
    $key_79da = { 2e a8 [2] 1c 8a [2] 1a bf [2] 34 bf [2] 0b a3 }

  condition:
    any of them
}