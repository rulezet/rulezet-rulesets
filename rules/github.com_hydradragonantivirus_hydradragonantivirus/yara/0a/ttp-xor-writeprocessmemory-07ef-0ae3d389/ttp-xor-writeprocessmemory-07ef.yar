rule TTP_XOR_WriteProcessMemory_07ef {
  strings:
    $key_07ef = { 50 9d [2] 62 bf [2] 64 8a [2] 4a 8a [2] 75 96 }

  condition:
    any of them
}