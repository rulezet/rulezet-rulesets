rule TTP_XOR_WriteProcessMemory_8726 {
  strings:
    $key_8726 = { d0 54 [2] e2 76 [2] e4 43 [2] ca 43 [2] f5 5f }

  condition:
    any of them
}