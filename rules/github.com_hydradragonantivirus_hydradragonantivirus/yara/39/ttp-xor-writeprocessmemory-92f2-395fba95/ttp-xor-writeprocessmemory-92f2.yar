rule TTP_XOR_WriteProcessMemory_92f2 {
  strings:
    $key_92f2 = { c5 80 [2] f7 a2 [2] f1 97 [2] df 97 [2] e0 8b }

  condition:
    any of them
}