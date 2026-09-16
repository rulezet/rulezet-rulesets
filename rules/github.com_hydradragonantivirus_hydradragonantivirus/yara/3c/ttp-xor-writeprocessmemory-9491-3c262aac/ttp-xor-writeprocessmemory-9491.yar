rule TTP_XOR_WriteProcessMemory_9491 {
  strings:
    $key_9491 = { c3 e3 [2] f1 c1 [2] f7 f4 [2] d9 f4 [2] e6 e8 }

  condition:
    any of them
}