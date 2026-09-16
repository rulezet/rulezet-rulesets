rule TTP_XOR_WriteProcessMemory_67ef {
  strings:
    $key_67ef = { 30 9d [2] 02 bf [2] 04 8a [2] 2a 8a [2] 15 96 }

  condition:
    any of them
}