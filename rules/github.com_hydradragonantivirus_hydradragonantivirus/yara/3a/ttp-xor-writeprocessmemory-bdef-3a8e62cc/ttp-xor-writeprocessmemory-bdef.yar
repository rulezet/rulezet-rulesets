rule TTP_XOR_WriteProcessMemory_bdef {
  strings:
    $key_bdef = { ea 9d [2] d8 bf [2] de 8a [2] f0 8a [2] cf 96 }

  condition:
    any of them
}