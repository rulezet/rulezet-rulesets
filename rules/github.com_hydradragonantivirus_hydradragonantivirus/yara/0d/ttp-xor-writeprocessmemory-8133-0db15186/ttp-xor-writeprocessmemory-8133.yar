rule TTP_XOR_WriteProcessMemory_8133 {
  strings:
    $key_8133 = { d6 41 [2] e4 63 [2] e2 56 [2] cc 56 [2] f3 4a }

  condition:
    any of them
}