rule TTP_XOR_WriteProcessMemory_57ef {
  strings:
    $key_57ef = { 00 9d [2] 32 bf [2] 34 8a [2] 1a 8a [2] 25 96 }

  condition:
    any of them
}