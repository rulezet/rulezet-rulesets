rule TTP_XOR_WriteProcessMemory_8153 {
  strings:
    $key_8153 = { d6 21 [2] e4 03 [2] e2 36 [2] cc 36 [2] f3 2a }

  condition:
    any of them
}