rule TTP_XOR_WriteProcessMemory_8730 {
  strings:
    $key_8730 = { d0 42 [2] e2 60 [2] e4 55 [2] ca 55 [2] f5 49 }

  condition:
    any of them
}