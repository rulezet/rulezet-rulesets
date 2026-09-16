rule TTP_XOR_WriteProcessMemory_97da {
  strings:
    $key_97da = { c0 a8 [2] f2 8a [2] f4 bf [2] da bf [2] e5 a3 }

  condition:
    any of them
}