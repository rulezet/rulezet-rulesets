rule TTP_XOR_WriteProcessMemory_8107 {
  strings:
    $key_8107 = { d6 75 [2] e4 57 [2] e2 62 [2] cc 62 [2] f3 7e }

  condition:
    any of them
}