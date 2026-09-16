rule TTP_XOR_WriteProcessMemory_57da {
  strings:
    $key_57da = { 00 a8 [2] 32 8a [2] 34 bf [2] 1a bf [2] 25 a3 }

  condition:
    any of them
}