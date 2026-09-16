rule TTP_XOR_WriteProcessMemory_52ef {
  strings:
    $key_52ef = { 05 9d [2] 37 bf [2] 31 8a [2] 1f 8a [2] 20 96 }

  condition:
    any of them
}