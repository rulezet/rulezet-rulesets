rule TTP_XOR_WriteProcessMemory_8703 {
  strings:
    $key_8703 = { d0 71 [2] e2 53 [2] e4 66 [2] ca 66 [2] f5 7a }

  condition:
    any of them
}