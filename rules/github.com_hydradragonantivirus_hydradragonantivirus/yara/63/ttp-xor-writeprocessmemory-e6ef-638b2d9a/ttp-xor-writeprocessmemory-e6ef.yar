rule TTP_XOR_WriteProcessMemory_e6ef {
  strings:
    $key_e6ef = { b1 9d [2] 83 bf [2] 85 8a [2] ab 8a [2] 94 96 }

  condition:
    any of them
}