rule TTP_XOR_WriteProcessMemory_9786 {
  strings:
    $key_9786 = { c0 f4 [2] f2 d6 [2] f4 e3 [2] da e3 [2] e5 ff }

  condition:
    any of them
}