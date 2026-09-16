rule TTP_XOR_WriteProcessMemory_17ef {
  strings:
    $key_17ef = { 40 9d [2] 72 bf [2] 74 8a [2] 5a 8a [2] 65 96 }

  condition:
    any of them
}