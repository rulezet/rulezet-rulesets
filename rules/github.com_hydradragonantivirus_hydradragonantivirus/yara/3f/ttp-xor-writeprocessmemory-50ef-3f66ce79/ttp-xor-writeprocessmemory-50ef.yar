rule TTP_XOR_WriteProcessMemory_50ef {
  strings:
    $key_50ef = { 07 9d [2] 35 bf [2] 33 8a [2] 1d 8a [2] 22 96 }

  condition:
    any of them
}