rule TTP_XOR_WriteProcessMemory_84da {
  strings:
    $key_84da = { d3 a8 [2] e1 8a [2] e7 bf [2] c9 bf [2] f6 a3 }

  condition:
    any of them
}