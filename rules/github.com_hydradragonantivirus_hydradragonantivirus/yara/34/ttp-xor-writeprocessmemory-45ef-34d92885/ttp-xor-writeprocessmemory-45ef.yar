rule TTP_XOR_WriteProcessMemory_45ef {
  strings:
    $key_45ef = { 12 9d [2] 20 bf [2] 26 8a [2] 08 8a [2] 37 96 }

  condition:
    any of them
}