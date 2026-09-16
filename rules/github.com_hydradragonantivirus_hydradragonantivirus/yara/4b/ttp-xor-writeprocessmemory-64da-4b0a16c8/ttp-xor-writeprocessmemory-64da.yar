rule TTP_XOR_WriteProcessMemory_64da {
  strings:
    $key_64da = { 33 a8 [2] 01 8a [2] 07 bf [2] 29 bf [2] 16 a3 }

  condition:
    any of them
}