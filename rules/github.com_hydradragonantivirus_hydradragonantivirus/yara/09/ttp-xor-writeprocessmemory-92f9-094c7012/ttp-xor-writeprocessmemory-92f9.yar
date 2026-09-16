rule TTP_XOR_WriteProcessMemory_92f9 {
  strings:
    $key_92f9 = { c5 8b [2] f7 a9 [2] f1 9c [2] df 9c [2] e0 80 }

  condition:
    any of them
}