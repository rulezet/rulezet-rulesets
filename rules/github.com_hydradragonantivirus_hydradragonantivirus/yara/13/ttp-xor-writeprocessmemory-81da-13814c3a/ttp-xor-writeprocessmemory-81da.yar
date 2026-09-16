rule TTP_XOR_WriteProcessMemory_81da {
  strings:
    $key_81da = { d6 a8 [2] e4 8a [2] e2 bf [2] cc bf [2] f3 a3 }

  condition:
    any of them
}