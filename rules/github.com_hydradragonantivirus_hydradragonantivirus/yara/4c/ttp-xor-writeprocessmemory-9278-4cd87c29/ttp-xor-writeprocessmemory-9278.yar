rule TTP_XOR_WriteProcessMemory_9278 {
  strings:
    $key_9278 = { c5 0a [2] f7 28 [2] f1 1d [2] df 1d [2] e0 01 }

  condition:
    any of them
}