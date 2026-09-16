rule TTP_XOR_WriteProcessMemory_94da {
  strings:
    $key_94da = { c3 a8 [2] f1 8a [2] f7 bf [2] d9 bf [2] e6 a3 }

  condition:
    any of them
}