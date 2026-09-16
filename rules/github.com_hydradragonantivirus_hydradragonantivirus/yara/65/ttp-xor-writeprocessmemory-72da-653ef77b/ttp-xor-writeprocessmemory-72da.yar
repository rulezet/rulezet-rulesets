rule TTP_XOR_WriteProcessMemory_72da {
  strings:
    $key_72da = { 25 a8 [2] 17 8a [2] 11 bf [2] 3f bf [2] 00 a3 }

  condition:
    any of them
}