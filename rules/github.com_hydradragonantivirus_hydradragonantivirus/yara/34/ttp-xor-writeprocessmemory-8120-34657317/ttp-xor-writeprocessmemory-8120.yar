rule TTP_XOR_WriteProcessMemory_8120 {
  strings:
    $key_8120 = { d6 52 [2] e4 70 [2] e2 45 [2] cc 45 [2] f3 59 }

  condition:
    any of them
}