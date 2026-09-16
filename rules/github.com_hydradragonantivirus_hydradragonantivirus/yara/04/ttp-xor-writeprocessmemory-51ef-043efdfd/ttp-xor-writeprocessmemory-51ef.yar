rule TTP_XOR_WriteProcessMemory_51ef {
  strings:
    $key_51ef = { 06 9d [2] 34 bf [2] 32 8a [2] 1c 8a [2] 23 96 }

  condition:
    any of them
}