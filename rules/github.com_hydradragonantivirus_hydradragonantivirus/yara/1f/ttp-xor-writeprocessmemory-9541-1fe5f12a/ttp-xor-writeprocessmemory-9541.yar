rule TTP_XOR_WriteProcessMemory_9541 {
  strings:
    $key_9541 = { c2 33 [2] f0 11 [2] f6 24 [2] d8 24 [2] e7 38 }

  condition:
    any of them
}