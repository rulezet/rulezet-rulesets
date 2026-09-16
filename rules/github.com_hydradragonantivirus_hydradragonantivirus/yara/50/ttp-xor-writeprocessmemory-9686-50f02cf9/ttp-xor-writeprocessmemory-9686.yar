rule TTP_XOR_WriteProcessMemory_9686 {
  strings:
    $key_9686 = { c1 f4 [2] f3 d6 [2] f5 e3 [2] db e3 [2] e4 ff }

  condition:
    any of them
}