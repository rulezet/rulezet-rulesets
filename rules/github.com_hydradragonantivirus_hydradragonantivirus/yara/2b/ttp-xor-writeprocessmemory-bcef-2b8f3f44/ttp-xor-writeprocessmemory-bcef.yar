rule TTP_XOR_WriteProcessMemory_bcef {
  strings:
    $key_bcef = { eb 9d [2] d9 bf [2] df 8a [2] f1 8a [2] ce 96 }

  condition:
    any of them
}