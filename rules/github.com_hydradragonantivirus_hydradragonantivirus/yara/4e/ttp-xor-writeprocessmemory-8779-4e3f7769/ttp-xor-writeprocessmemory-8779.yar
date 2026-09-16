rule TTP_XOR_WriteProcessMemory_8779 {
  strings:
    $key_8779 = { d0 0b [2] e2 29 [2] e4 1c [2] ca 1c [2] f5 00 }

  condition:
    any of them
}