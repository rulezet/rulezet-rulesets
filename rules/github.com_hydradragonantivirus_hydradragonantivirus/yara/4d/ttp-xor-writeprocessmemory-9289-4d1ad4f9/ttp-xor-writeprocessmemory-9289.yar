rule TTP_XOR_WriteProcessMemory_9289 {
  strings:
    $key_9289 = { c5 fb [2] f7 d9 [2] f1 ec [2] df ec [2] e0 f0 }

  condition:
    any of them
}