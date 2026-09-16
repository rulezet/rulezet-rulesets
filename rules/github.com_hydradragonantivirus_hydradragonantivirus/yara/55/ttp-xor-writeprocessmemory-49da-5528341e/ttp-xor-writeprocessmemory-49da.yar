rule TTP_XOR_WriteProcessMemory_49da {
  strings:
    $key_49da = { 1e a8 [2] 2c 8a [2] 2a bf [2] 04 bf [2] 3b a3 }

  condition:
    any of them
}