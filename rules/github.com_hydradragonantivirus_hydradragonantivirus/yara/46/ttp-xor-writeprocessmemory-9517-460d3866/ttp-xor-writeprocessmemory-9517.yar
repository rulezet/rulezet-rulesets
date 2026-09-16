rule TTP_XOR_WriteProcessMemory_9517 {
  strings:
    $key_9517 = { c2 65 [2] f0 47 [2] f6 72 [2] d8 72 [2] e7 6e }

  condition:
    any of them
}