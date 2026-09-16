rule TTP_XOR_WriteProcessMemory_bada {
  strings:
    $key_bada = { ed a8 [2] df 8a [2] d9 bf [2] f7 bf [2] c8 a3 }

  condition:
    any of them
}