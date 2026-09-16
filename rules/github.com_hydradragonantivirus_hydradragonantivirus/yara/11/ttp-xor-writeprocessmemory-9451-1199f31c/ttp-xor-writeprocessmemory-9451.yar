rule TTP_XOR_WriteProcessMemory_9451 {
  strings:
    $key_9451 = { c3 23 [2] f1 01 [2] f7 34 [2] d9 34 [2] e6 28 }

  condition:
    any of them
}