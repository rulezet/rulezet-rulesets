rule TTP_XOR_WriteProcessMemory_32da {
  strings:
    $key_32da = { 65 a8 [2] 57 8a [2] 51 bf [2] 7f bf [2] 40 a3 }

  condition:
    any of them
}