rule TTP_XOR_WriteProcessMemory_9281 {
  strings:
    $key_9281 = { c5 f3 [2] f7 d1 [2] f1 e4 [2] df e4 [2] e0 f8 }

  condition:
    any of them
}