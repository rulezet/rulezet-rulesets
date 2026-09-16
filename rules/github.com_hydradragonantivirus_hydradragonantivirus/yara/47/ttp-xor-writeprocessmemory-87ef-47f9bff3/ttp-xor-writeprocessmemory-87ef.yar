rule TTP_XOR_WriteProcessMemory_87ef {
  strings:
    $key_87ef = { d0 9d [2] e2 bf [2] e4 8a [2] ca 8a [2] f5 96 }

  condition:
    any of them
}