rule TTP_XOR_WriteProcessMemory_e7ef {
  strings:
    $key_e7ef = { b0 9d [2] 82 bf [2] 84 8a [2] aa 8a [2] 95 96 }

  condition:
    any of them
}