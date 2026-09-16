rule TTP_XOR_WriteProcessMemory_8702 {
  strings:
    $key_8702 = { d0 70 [2] e2 52 [2] e4 67 [2] ca 67 [2] f5 7b }

  condition:
    any of them
}