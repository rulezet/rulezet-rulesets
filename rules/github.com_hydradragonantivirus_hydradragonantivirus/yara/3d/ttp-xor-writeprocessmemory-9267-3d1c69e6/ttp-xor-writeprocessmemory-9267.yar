rule TTP_XOR_WriteProcessMemory_9267 {
  strings:
    $key_9267 = { c5 15 [2] f7 37 [2] f1 02 [2] df 02 [2] e0 1e }

  condition:
    any of them
}