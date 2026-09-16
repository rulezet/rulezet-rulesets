rule TTP_XOR_WriteProcessMemory_81a6 {
  strings:
    $key_81a6 = { d6 d4 [2] e4 f6 [2] e2 c3 [2] cc c3 [2] f3 df }

  condition:
    any of them
}