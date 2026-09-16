rule TTP_XOR_WriteProcessMemory_34da {
  strings:
    $key_34da = { 63 a8 [2] 51 8a [2] 57 bf [2] 79 bf [2] 46 a3 }

  condition:
    any of them
}