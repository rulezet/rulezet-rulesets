rule TTP_XOR_WriteProcessMemory_95a2 {
  strings:
    $key_95a2 = { c2 d0 [2] f0 f2 [2] f6 c7 [2] d8 c7 [2] e7 db }

  condition:
    any of them
}