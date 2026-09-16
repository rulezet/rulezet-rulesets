rule TTP_XOR_WriteProcessMemory_f1ef {
  strings:
    $key_f1ef = { a6 9d [2] 94 bf [2] 92 8a [2] bc 8a [2] 83 96 }

  condition:
    any of them
}