rule TTP_XOR_WriteProcessMemory_9220 {
  strings:
    $key_9220 = { c5 52 [2] f7 70 [2] f1 45 [2] df 45 [2] e0 59 }

  condition:
    any of them
}