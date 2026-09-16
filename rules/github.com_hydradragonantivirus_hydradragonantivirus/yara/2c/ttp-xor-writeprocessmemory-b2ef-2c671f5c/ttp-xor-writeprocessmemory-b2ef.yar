rule TTP_XOR_WriteProcessMemory_b2ef {
  strings:
    $key_b2ef = { e5 9d [2] d7 bf [2] d1 8a [2] ff 8a [2] c0 96 }

  condition:
    any of them
}