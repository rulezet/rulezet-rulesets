rule TTP_XOR_WriteProcessMemory_8762 {
  strings:
    $key_8762 = { d0 10 [2] e2 32 [2] e4 07 [2] ca 07 [2] f5 1b }

  condition:
    any of them
}