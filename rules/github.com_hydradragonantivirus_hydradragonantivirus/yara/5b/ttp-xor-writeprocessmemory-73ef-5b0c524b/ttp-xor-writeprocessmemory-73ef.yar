rule TTP_XOR_WriteProcessMemory_73ef {
  strings:
    $key_73ef = { 24 9d [2] 16 bf [2] 10 8a [2] 3e 8a [2] 01 96 }

  condition:
    any of them
}