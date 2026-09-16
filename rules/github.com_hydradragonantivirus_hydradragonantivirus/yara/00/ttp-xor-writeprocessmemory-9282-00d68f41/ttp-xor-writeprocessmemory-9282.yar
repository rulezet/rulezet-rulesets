rule TTP_XOR_WriteProcessMemory_9282 {
  strings:
    $key_9282 = { c5 f0 [2] f7 d2 [2] f1 e7 [2] df e7 [2] e0 fb }

  condition:
    any of them
}