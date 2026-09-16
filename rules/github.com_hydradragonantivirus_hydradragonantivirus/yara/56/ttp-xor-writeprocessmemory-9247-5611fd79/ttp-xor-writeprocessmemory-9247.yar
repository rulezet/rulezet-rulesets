rule TTP_XOR_WriteProcessMemory_9247 {
  strings:
    $key_9247 = { c5 35 [2] f7 17 [2] f1 22 [2] df 22 [2] e0 3e }

  condition:
    any of them
}