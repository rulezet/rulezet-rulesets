rule TTP_XOR_WriteProcessMemory_92f3 {
  strings:
    $key_92f3 = { c5 81 [2] f7 a3 [2] f1 96 [2] df 96 [2] e0 8a }

  condition:
    any of them
}