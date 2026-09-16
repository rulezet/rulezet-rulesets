rule TTP_XOR_WriteProcessMemory_9091 {
  strings:
    $key_9091 = { c7 e3 [2] f5 c1 [2] f3 f4 [2] dd f4 [2] e2 e8 }

  condition:
    any of them
}