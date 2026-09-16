rule TTP_XOR_WriteProcessMemory_11ef {
  strings:
    $key_11ef = { 46 9d [2] 74 bf [2] 72 8a [2] 5c 8a [2] 63 96 }

  condition:
    any of them
}