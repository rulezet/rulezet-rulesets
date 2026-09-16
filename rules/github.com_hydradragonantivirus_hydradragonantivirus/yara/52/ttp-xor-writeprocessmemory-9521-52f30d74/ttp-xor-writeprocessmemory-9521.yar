rule TTP_XOR_WriteProcessMemory_9521 {
  strings:
    $key_9521 = { c2 53 [2] f0 71 [2] f6 44 [2] d8 44 [2] e7 58 }

  condition:
    any of them
}