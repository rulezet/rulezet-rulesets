rule TTP_XOR_WriteProcessMemory_e1ef {
  strings:
    $key_e1ef = { b6 9d [2] 84 bf [2] 82 8a [2] ac 8a [2] 93 96 }

  condition:
    any of them
}