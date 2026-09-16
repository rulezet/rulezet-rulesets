rule TTP_XOR_WriteProcessMemory_55ef {
  strings:
    $key_55ef = { 02 9d [2] 30 bf [2] 36 8a [2] 18 8a [2] 27 96 }

  condition:
    any of them
}