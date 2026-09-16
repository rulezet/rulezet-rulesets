rule TTP_XOR_WriteProcessMemory_92da {
  strings:
    $key_92da = { c5 a8 [2] f7 8a [2] f1 bf [2] df bf [2] e0 a3 }

  condition:
    any of them
}