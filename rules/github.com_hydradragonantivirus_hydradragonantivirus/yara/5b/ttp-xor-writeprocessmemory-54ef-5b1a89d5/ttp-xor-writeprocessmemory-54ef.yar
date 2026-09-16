rule TTP_XOR_WriteProcessMemory_54ef {
  strings:
    $key_54ef = { 03 9d [2] 31 bf [2] 37 8a [2] 19 8a [2] 26 96 }

  condition:
    any of them
}