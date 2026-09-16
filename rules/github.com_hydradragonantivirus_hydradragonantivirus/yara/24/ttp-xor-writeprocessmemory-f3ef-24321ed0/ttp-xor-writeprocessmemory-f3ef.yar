rule TTP_XOR_WriteProcessMemory_f3ef {
  strings:
    $key_f3ef = { a4 9d [2] 96 bf [2] 90 8a [2] be 8a [2] 81 96 }

  condition:
    any of them
}