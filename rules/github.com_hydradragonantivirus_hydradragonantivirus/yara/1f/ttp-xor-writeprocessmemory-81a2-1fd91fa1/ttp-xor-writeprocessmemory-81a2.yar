rule TTP_XOR_WriteProcessMemory_81a2 {
  strings:
    $key_81a2 = { d6 d0 [2] e4 f2 [2] e2 c7 [2] cc c7 [2] f3 db }

  condition:
    any of them
}