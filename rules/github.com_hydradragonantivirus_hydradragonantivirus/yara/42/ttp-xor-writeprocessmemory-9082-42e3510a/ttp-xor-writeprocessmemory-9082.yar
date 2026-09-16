rule TTP_XOR_WriteProcessMemory_9082 {
  strings:
    $key_9082 = { c7 f0 [2] f5 d2 [2] f3 e7 [2] dd e7 [2] e2 fb }

  condition:
    any of them
}