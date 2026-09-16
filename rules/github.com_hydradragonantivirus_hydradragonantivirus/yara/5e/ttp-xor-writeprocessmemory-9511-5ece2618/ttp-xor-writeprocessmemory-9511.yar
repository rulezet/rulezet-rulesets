rule TTP_XOR_WriteProcessMemory_9511 {
  strings:
    $key_9511 = { c2 63 [2] f0 41 [2] f6 74 [2] d8 74 [2] e7 68 }

  condition:
    any of them
}