rule TTP_XOR_WriteProcessMemory_8132 {
  strings:
    $key_8132 = { d6 40 [2] e4 62 [2] e2 57 [2] cc 57 [2] f3 4b }

  condition:
    any of them
}