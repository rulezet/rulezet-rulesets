rule TTP_XOR_WriteProcessMemory_bbda {
  strings:
    $key_bbda = { ec a8 [2] de 8a [2] d8 bf [2] f6 bf [2] c9 a3 }

  condition:
    any of them
}