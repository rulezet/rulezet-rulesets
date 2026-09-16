rule TTP_XOR_WriteProcessMemory_32ef {
  strings:
    $key_32ef = { 65 9d [2] 57 bf [2] 51 8a [2] 7f 8a [2] 40 96 }

  condition:
    any of them
}