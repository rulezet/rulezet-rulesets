rule TTP_XOR_WriteProcessMemory_8745 {
  strings:
    $key_8745 = { d0 37 [2] e2 15 [2] e4 20 [2] ca 20 [2] f5 3c }

  condition:
    any of them
}