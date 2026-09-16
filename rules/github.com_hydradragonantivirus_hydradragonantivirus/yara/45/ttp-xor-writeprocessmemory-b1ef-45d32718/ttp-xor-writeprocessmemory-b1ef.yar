rule TTP_XOR_WriteProcessMemory_b1ef {
  strings:
    $key_b1ef = { e6 9d [2] d4 bf [2] d2 8a [2] fc 8a [2] c3 96 }

  condition:
    any of them
}