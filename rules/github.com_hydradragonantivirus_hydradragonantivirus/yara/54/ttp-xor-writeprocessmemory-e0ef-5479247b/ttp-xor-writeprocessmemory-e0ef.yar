rule TTP_XOR_WriteProcessMemory_e0ef {
  strings:
    $key_e0ef = { b7 9d [2] 85 bf [2] 83 8a [2] ad 8a [2] 92 96 }

  condition:
    any of them
}