rule TTP_XOR_WriteProcessMemory_b0ef {
  strings:
    $key_b0ef = { e7 9d [2] d5 bf [2] d3 8a [2] fd 8a [2] c2 96 }

  condition:
    any of them
}