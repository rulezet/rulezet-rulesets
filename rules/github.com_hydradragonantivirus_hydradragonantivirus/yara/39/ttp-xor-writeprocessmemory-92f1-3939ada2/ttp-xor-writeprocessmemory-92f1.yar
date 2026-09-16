rule TTP_XOR_WriteProcessMemory_92f1 {
  strings:
    $key_92f1 = { c5 83 [2] f7 a1 [2] f1 94 [2] df 94 [2] e0 88 }

  condition:
    any of them
}