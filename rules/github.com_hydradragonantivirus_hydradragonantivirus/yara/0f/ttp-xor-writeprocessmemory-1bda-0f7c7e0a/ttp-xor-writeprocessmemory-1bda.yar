rule TTP_XOR_WriteProcessMemory_1bda {
  strings:
    $key_1bda = { 4c a8 [2] 7e 8a [2] 78 bf [2] 56 bf [2] 69 a3 }

  condition:
    any of them
}