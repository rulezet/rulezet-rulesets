rule TTP_XOR_WriteProcessMemory_9470 {
  strings:
    $key_9470 = { c3 02 [2] f1 20 [2] f7 15 [2] d9 15 [2] e6 09 }

  condition:
    any of them
}