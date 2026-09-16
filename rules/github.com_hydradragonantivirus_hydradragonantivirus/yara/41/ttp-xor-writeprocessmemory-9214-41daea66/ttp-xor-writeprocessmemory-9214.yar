rule TTP_XOR_WriteProcessMemory_9214 {
  strings:
    $key_9214 = { c5 66 [2] f7 44 [2] f1 71 [2] df 71 [2] e0 6d }

  condition:
    any of them
}