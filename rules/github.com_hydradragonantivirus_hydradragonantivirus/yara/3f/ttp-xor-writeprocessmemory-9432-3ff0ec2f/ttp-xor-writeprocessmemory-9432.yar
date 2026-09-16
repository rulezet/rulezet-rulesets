rule TTP_XOR_WriteProcessMemory_9432 {
  strings:
    $key_9432 = { c3 40 [2] f1 62 [2] f7 57 [2] d9 57 [2] e6 4b }

  condition:
    any of them
}