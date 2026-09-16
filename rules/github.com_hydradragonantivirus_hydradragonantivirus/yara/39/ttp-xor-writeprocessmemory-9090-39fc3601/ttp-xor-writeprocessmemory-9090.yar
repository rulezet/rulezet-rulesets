rule TTP_XOR_WriteProcessMemory_9090 {
  strings:
    $key_9090 = { c7 e2 [2] f5 c0 [2] f3 f5 [2] dd f5 [2] e2 e9 }

  condition:
    any of them
}