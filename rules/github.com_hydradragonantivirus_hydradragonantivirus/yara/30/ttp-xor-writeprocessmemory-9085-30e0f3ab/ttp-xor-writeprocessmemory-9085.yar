rule TTP_XOR_WriteProcessMemory_9085 {
  strings:
    $key_9085 = { c7 f7 [2] f5 d5 [2] f3 e0 [2] dd e0 [2] e2 fc }

  condition:
    any of them
}