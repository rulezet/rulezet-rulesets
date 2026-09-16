rule TTP_XOR_WriteProcessMemory_73da {
  strings:
    $key_73da = { 24 a8 [2] 16 8a [2] 10 bf [2] 3e bf [2] 01 a3 }

  condition:
    any of them
}