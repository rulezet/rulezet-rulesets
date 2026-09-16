rule TTP_XOR_WriteProcessMemory_8103 {
  strings:
    $key_8103 = { d6 71 [2] e4 53 [2] e2 66 [2] cc 66 [2] f3 7a }

  condition:
    any of them
}