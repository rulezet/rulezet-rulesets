rule TTP_XOR_WriteProcessMemory_9547 {
  strings:
    $key_9547 = { c2 35 [2] f0 17 [2] f6 22 [2] d8 22 [2] e7 3e }

  condition:
    any of them
}