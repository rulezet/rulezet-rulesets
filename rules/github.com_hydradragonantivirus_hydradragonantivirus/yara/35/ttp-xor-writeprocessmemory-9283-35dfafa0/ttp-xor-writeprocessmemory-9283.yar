rule TTP_XOR_WriteProcessMemory_9283 {
  strings:
    $key_9283 = { c5 f1 [2] f7 d3 [2] f1 e6 [2] df e6 [2] e0 fa }

  condition:
    any of them
}