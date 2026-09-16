rule TTP_XOR_WriteProcessMemory_9294 {
  strings:
    $key_9294 = { c5 e6 [2] f7 c4 [2] f1 f1 [2] df f1 [2] e0 ed }

  condition:
    any of them
}