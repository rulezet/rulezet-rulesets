rule TTP_XOR_WriteProcessMemory_9561 {
  strings:
    $key_9561 = { c2 13 [2] f0 31 [2] f6 04 [2] d8 04 [2] e7 18 }

  condition:
    any of them
}