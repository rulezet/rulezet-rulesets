rule TTP_XOR_WriteProcessMemory_66ef {
  strings:
    $key_66ef = { 31 9d [2] 03 bf [2] 05 8a [2] 2b 8a [2] 14 96 }

  condition:
    any of them
}