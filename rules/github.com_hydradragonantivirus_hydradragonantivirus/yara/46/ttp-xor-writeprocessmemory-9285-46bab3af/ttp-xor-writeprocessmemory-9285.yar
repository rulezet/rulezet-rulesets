rule TTP_XOR_WriteProcessMemory_9285 {
  strings:
    $key_9285 = { c5 f7 [2] f7 d5 [2] f1 e0 [2] df e0 [2] e0 fc }

  condition:
    any of them
}