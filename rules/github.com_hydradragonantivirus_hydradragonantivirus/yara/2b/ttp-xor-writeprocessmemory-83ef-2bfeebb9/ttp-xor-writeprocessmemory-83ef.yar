rule TTP_XOR_WriteProcessMemory_83ef {
  strings:
    $key_83ef = { d4 9d [2] e6 bf [2] e0 8a [2] ce 8a [2] f1 96 }

  condition:
    any of them
}