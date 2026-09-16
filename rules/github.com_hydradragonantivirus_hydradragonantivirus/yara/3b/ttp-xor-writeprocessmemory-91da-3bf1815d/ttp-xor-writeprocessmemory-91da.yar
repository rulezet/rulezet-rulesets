rule TTP_XOR_WriteProcessMemory_91da {
  strings:
    $key_91da = { c6 a8 [2] f4 8a [2] f2 bf [2] dc bf [2] e3 a3 }

  condition:
    any of them
}