rule TTP_XOR_WriteProcessMemory_94ef {
  strings:
    $key_94ef = { c3 9d [2] f1 bf [2] f7 8a [2] d9 8a [2] e6 96 }

  condition:
    any of them
}