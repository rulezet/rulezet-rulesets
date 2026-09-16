rule TTP_XOR_WriteProcessMemory_41ef {
  strings:
    $key_41ef = { 16 9d [2] 24 bf [2] 22 8a [2] 0c 8a [2] 33 96 }

  condition:
    any of them
}