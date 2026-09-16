rule TTP_XOR_WriteProcessMemory_9783 {
  strings:
    $key_9783 = { c0 f1 [2] f2 d3 [2] f4 e6 [2] da e6 [2] e5 fa }

  condition:
    any of them
}