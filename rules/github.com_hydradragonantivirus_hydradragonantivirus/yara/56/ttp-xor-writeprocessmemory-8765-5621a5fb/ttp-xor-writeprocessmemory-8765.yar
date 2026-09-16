rule TTP_XOR_WriteProcessMemory_8765 {
  strings:
    $key_8765 = { d0 17 [2] e2 35 [2] e4 00 [2] ca 00 [2] f5 1c }

  condition:
    any of them
}