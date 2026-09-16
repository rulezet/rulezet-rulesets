rule TTP_XOR_WriteProcessMemory_30ef {
  strings:
    $key_30ef = { 67 9d [2] 55 bf [2] 53 8a [2] 7d 8a [2] 42 96 }

  condition:
    any of them
}