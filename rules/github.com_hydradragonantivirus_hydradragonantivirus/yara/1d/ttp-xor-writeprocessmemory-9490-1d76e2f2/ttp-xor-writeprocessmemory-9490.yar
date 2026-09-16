rule TTP_XOR_WriteProcessMemory_9490 {
  strings:
    $key_9490 = { c3 e2 [2] f1 c0 [2] f7 f5 [2] d9 f5 [2] e6 e9 }

  condition:
    any of them
}