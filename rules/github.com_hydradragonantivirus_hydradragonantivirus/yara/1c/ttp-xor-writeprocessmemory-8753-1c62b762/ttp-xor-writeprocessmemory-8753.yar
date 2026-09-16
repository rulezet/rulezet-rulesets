rule TTP_XOR_WriteProcessMemory_8753 {
  strings:
    $key_8753 = { d0 21 [2] e2 03 [2] e4 36 [2] ca 36 [2] f5 2a }

  condition:
    any of them
}