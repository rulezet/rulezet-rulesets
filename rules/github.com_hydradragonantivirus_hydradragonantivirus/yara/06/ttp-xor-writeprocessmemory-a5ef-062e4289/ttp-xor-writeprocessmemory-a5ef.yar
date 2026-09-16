rule TTP_XOR_WriteProcessMemory_a5ef {
  strings:
    $key_a5ef = { f2 9d [2] c0 bf [2] c6 8a [2] e8 8a [2] d7 96 }

  condition:
    any of them
}