rule TTP_XOR_WriteProcessMemory_9400 {
  strings:
    $key_9400 = { c3 72 [2] f1 50 [2] f7 65 [2] d9 65 [2] e6 79 }

  condition:
    any of them
}