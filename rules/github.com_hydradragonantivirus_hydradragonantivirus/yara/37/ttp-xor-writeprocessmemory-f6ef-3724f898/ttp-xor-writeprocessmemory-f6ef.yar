rule TTP_XOR_WriteProcessMemory_f6ef {
  strings:
    $key_f6ef = { a1 9d [2] 93 bf [2] 95 8a [2] bb 8a [2] 84 96 }

  condition:
    any of them
}