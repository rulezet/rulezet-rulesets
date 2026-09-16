rule TTP_XOR_WriteProcessMemory_9554 {
  strings:
    $key_9554 = { c2 26 [2] f0 04 [2] f6 31 [2] d8 31 [2] e7 2d }

  condition:
    any of them
}