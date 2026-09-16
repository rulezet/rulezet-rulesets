rule TTP_XOR_WriteProcessMemory_8707 {
  strings:
    $key_8707 = { d0 75 [2] e2 57 [2] e4 62 [2] ca 62 [2] f5 7e }

  condition:
    any of them
}