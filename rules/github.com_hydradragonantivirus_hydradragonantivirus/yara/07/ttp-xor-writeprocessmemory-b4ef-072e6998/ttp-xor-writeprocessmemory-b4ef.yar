rule TTP_XOR_WriteProcessMemory_b4ef {
  strings:
    $key_b4ef = { e3 9d [2] d1 bf [2] d7 8a [2] f9 8a [2] c6 96 }

  condition:
    any of them
}