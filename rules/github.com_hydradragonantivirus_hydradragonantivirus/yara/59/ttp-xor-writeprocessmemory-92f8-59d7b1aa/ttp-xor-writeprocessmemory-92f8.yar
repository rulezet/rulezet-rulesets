rule TTP_XOR_WriteProcessMemory_92f8 {
  strings:
    $key_92f8 = { c5 8a [2] f7 a8 [2] f1 9d [2] df 9d [2] e0 81 }

  condition:
    any of them
}