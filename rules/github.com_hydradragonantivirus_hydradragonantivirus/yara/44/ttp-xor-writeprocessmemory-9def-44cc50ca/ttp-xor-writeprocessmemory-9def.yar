rule TTP_XOR_WriteProcessMemory_9def {
  strings:
    $key_9def = { ca 9d [2] f8 bf [2] fe 8a [2] d0 8a [2] ef 96 }

  condition:
    any of them
}