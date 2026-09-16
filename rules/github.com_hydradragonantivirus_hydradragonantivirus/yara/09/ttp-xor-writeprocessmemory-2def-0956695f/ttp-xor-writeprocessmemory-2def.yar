rule TTP_XOR_WriteProcessMemory_2def {
  strings:
    $key_2def = { 7a 9d [2] 48 bf [2] 4e 8a [2] 60 8a [2] 5f 96 }

  condition:
    any of them
}