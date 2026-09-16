rule TTP_XOR_WriteProcessMemory_81a4 {
  strings:
    $key_81a4 = { d6 d6 [2] e4 f4 [2] e2 c1 [2] cc c1 [2] f3 dd }

  condition:
    any of them
}