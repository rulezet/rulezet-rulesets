rule TTP_XOR_WriteProcessMemory_9480 {
  strings:
    $key_9480 = { c3 f2 [2] f1 d0 [2] f7 e5 [2] d9 e5 [2] e6 f9 }

  condition:
    any of them
}