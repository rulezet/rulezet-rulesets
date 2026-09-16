rule TTP_XOR_WriteProcessMemory_9228 {
  strings:
    $key_9228 = { c5 5a [2] f7 78 [2] f1 4d [2] df 4d [2] e0 51 }

  condition:
    any of them
}