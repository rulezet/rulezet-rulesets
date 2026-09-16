rule TTP_XOR_WriteProcessMemory_8708 {
  strings:
    $key_8708 = { d0 7a [2] e2 58 [2] e4 6d [2] ca 6d [2] f5 71 }

  condition:
    any of them
}