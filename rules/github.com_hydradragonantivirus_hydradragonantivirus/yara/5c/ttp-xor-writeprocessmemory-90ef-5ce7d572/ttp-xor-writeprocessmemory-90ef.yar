rule TTP_XOR_WriteProcessMemory_90ef {
  strings:
    $key_90ef = { c7 9d [2] f5 bf [2] f3 8a [2] dd 8a [2] e2 96 }

  condition:
    any of them
}