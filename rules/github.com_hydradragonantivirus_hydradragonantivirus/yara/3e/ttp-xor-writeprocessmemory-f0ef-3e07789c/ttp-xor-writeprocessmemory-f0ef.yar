rule TTP_XOR_WriteProcessMemory_f0ef {
  strings:
    $key_f0ef = { a7 9d [2] 95 bf [2] 93 8a [2] bd 8a [2] 82 96 }

  condition:
    any of them
}