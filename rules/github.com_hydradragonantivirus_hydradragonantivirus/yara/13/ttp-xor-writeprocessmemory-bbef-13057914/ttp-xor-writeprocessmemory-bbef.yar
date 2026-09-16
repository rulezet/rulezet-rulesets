rule TTP_XOR_WriteProcessMemory_bbef {
  strings:
    $key_bbef = { ec 9d [2] de bf [2] d8 8a [2] f6 8a [2] c9 96 }

  condition:
    any of them
}