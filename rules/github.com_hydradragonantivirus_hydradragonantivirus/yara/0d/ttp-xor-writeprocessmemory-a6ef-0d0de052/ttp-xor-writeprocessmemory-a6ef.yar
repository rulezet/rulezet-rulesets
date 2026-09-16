rule TTP_XOR_WriteProcessMemory_a6ef {
  strings:
    $key_a6ef = { f1 9d [2] c3 bf [2] c5 8a [2] eb 8a [2] d4 96 }

  condition:
    any of them
}