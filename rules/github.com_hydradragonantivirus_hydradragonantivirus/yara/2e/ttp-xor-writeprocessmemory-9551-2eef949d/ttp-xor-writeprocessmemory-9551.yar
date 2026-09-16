rule TTP_XOR_WriteProcessMemory_9551 {
  strings:
    $key_9551 = { c2 23 [2] f0 01 [2] f6 34 [2] d8 34 [2] e7 28 }

  condition:
    any of them
}