rule TTP_XOR_WriteProcessMemory_8624 {
  strings:
    $key_8624 = { d1 56 [2] e3 74 [2] e5 41 [2] cb 41 [2] f4 5d }

  condition:
    any of them
}