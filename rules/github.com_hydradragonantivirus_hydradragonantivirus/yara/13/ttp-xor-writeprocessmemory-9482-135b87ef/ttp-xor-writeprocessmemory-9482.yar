rule TTP_XOR_WriteProcessMemory_9482 {
  strings:
    $key_9482 = { c3 f0 [2] f1 d2 [2] f7 e7 [2] d9 e7 [2] e6 fb }

  condition:
    any of them
}