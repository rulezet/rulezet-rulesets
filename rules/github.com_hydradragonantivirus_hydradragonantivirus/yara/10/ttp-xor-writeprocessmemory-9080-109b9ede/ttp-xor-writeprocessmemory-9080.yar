rule TTP_XOR_WriteProcessMemory_9080 {
  strings:
    $key_9080 = { c7 f2 [2] f5 d0 [2] f3 e5 [2] dd e5 [2] e2 f9 }

  condition:
    any of them
}