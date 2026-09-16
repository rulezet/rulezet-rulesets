rule TTP_XOR_WriteProcessMemory_9454 {
  strings:
    $key_9454 = { c3 26 [2] f1 04 [2] f7 31 [2] d9 31 [2] e6 2d }

  condition:
    any of them
}