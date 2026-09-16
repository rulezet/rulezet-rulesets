rule TTP_XOR_WriteProcessMemory_8ada {
  strings:
    $key_8ada = { dd a8 [2] ef 8a [2] e9 bf [2] c7 bf [2] f8 a3 }

  condition:
    any of them
}