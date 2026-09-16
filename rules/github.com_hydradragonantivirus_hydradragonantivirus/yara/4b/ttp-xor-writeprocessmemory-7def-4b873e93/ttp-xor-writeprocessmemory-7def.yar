rule TTP_XOR_WriteProcessMemory_7def {
  strings:
    $key_7def = { 2a 9d [2] 18 bf [2] 1e 8a [2] 30 8a [2] 0f 96 }

  condition:
    any of them
}