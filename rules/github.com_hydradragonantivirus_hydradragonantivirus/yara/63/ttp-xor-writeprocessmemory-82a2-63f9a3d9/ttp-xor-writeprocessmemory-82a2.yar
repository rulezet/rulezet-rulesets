rule TTP_XOR_WriteProcessMemory_82a2 {
  strings:
    $key_82a2 = { d5 d0 [2] e7 f2 [2] e1 c7 [2] cf c7 [2] f0 db }

  condition:
    any of them
}