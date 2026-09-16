rule TTP_XOR_WriteProcessMemory_9477 {
  strings:
    $key_9477 = { c3 05 [2] f1 27 [2] f7 12 [2] d9 12 [2] e6 0e }

  condition:
    any of them
}