rule TTP_XOR_WriteProcessMemory_9238 {
  strings:
    $key_9238 = { c5 4a [2] f7 68 [2] f1 5d [2] df 5d [2] e0 41 }

  condition:
    any of them
}