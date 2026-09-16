rule TTP_XOR_WriteProcessMemory_9683 {
  strings:
    $key_9683 = { c1 f1 [2] f3 d3 [2] f5 e6 [2] db e6 [2] e4 fa }

  condition:
    any of them
}