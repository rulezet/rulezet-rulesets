rule TTP_XOR_WriteProcessMemory_9474 {
  strings:
    $key_9474 = { c3 06 [2] f1 24 [2] f7 11 [2] d9 11 [2] e6 0d }

  condition:
    any of them
}