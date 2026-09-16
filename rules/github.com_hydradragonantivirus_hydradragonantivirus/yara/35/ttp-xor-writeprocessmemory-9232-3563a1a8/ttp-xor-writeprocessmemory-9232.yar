rule TTP_XOR_WriteProcessMemory_9232 {
  strings:
    $key_9232 = { c5 40 [2] f7 62 [2] f1 57 [2] df 57 [2] e0 4b }

  condition:
    any of them
}