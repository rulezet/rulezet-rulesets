rule TTP_XOR_WriteProcessMemory_9210 {
  strings:
    $key_9210 = { c5 62 [2] f7 40 [2] f1 75 [2] df 75 [2] e0 69 }

  condition:
    any of them
}