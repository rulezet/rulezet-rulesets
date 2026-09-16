rule TTP_XOR_WriteProcessMemory_05ef {
  strings:
    $key_05ef = { 52 9d [2] 60 bf [2] 66 8a [2] 48 8a [2] 77 96 }

  condition:
    any of them
}