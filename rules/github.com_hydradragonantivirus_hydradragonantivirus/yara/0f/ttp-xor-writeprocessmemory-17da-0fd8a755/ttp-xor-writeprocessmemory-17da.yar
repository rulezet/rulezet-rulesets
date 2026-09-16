rule TTP_XOR_WriteProcessMemory_17da {
  strings:
    $key_17da = { 40 a8 [2] 72 8a [2] 74 bf [2] 5a bf [2] 65 a3 }

  condition:
    any of them
}