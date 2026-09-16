rule TTP_XOR_WriteProcessMemory_9083 {
  strings:
    $key_9083 = { c7 f1 [2] f5 d3 [2] f3 e6 [2] dd e6 [2] e2 fa }

  condition:
    any of them
}