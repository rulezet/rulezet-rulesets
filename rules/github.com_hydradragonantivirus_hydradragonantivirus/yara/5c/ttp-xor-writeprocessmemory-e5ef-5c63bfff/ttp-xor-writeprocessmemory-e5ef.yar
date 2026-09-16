rule TTP_XOR_WriteProcessMemory_e5ef {
  strings:
    $key_e5ef = { b2 9d [2] 80 bf [2] 86 8a [2] a8 8a [2] 97 96 }

  condition:
    any of them
}