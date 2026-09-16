rule TTP_XOR_WriteProcessMemory_9382 {
  strings:
    $key_9382 = { c4 f0 [2] f6 d2 [2] f0 e7 [2] de e7 [2] e1 fb }

  condition:
    any of them
}