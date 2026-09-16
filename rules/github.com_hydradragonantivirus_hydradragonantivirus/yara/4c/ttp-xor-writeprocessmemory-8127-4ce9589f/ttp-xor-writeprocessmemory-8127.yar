rule TTP_XOR_WriteProcessMemory_8127 {
  strings:
    $key_8127 = { d6 55 [2] e4 77 [2] e2 42 [2] cc 42 [2] f3 5e }

  condition:
    any of them
}