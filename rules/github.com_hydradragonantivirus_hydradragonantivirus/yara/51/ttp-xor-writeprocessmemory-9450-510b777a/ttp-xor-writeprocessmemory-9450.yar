rule TTP_XOR_WriteProcessMemory_9450 {
  strings:
    $key_9450 = { c3 22 [2] f1 00 [2] f7 35 [2] d9 35 [2] e6 29 }

  condition:
    any of them
}