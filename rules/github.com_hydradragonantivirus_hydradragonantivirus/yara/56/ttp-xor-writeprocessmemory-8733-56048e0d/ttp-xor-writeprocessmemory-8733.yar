rule TTP_XOR_WriteProcessMemory_8733 {
  strings:
    $key_8733 = { d0 41 [2] e2 63 [2] e4 56 [2] ca 56 [2] f5 4a }

  condition:
    any of them
}