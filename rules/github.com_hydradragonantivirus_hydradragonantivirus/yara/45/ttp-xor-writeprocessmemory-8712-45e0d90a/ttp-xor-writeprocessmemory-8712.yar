rule TTP_XOR_WriteProcessMemory_8712 {
  strings:
    $key_8712 = { d0 60 [2] e2 42 [2] e4 77 [2] ca 77 [2] f5 6b }

  condition:
    any of them
}