rule TTP_XOR_WriteProcessMemory_82ef {
  strings:
    $key_82ef = { d5 9d [2] e7 bf [2] e1 8a [2] cf 8a [2] f0 96 }

  condition:
    any of them
}