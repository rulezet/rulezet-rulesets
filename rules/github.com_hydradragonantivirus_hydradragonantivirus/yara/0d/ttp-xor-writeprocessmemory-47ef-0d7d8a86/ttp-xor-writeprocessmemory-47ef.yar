rule TTP_XOR_WriteProcessMemory_47ef {
  strings:
    $key_47ef = { 10 9d [2] 22 bf [2] 24 8a [2] 0a 8a [2] 35 96 }

  condition:
    any of them
}