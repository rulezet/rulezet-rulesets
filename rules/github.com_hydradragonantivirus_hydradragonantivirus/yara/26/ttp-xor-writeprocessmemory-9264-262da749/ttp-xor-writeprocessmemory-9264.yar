rule TTP_XOR_WriteProcessMemory_9264 {
  strings:
    $key_9264 = { c5 16 [2] f7 34 [2] f1 01 [2] df 01 [2] e0 1d }

  condition:
    any of them
}