rule TTP_XOR_WriteProcessMemory_92ef {
  strings:
    $key_92ef = { c5 9d [2] f7 bf [2] f1 8a [2] df 8a [2] e0 96 }

  condition:
    any of them
}