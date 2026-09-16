rule TTP_XOR_WriteProcessMemory_9483 {
  strings:
    $key_9483 = { c3 f1 [2] f1 d3 [2] f7 e6 [2] d9 e6 [2] e6 fa }

  condition:
    any of them
}