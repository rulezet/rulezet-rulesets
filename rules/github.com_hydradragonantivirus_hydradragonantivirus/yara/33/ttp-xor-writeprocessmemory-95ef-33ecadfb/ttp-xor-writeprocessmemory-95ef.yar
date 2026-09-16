rule TTP_XOR_WriteProcessMemory_95ef {
  strings:
    $key_95ef = { c2 9d [2] f0 bf [2] f6 8a [2] d8 8a [2] e7 96 }

  condition:
    any of them
}