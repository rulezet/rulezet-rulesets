rule TTP_XOR_WriteProcessMemory_9185 {
  strings:
    $key_9185 = { c6 f7 [2] f4 d5 [2] f2 e0 [2] dc e0 [2] e3 fc }

  condition:
    any of them
}