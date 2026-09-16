rule TTP_XOR_WriteProcessMemory_8dda {
  strings:
    $key_8dda = { da a8 [2] e8 8a [2] ee bf [2] c0 bf [2] ff a3 }

  condition:
    any of them
}