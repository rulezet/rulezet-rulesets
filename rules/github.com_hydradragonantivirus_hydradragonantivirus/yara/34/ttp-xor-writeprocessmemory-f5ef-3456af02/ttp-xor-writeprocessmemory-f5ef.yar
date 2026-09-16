rule TTP_XOR_WriteProcessMemory_f5ef {
  strings:
    $key_f5ef = { a2 9d [2] 90 bf [2] 96 8a [2] b8 8a [2] 87 96 }

  condition:
    any of them
}