rule TTP_XOR_WriteProcessMemory_8115 {
  strings:
    $key_8115 = { d6 67 [2] e4 45 [2] e2 70 [2] cc 70 [2] f3 6c }

  condition:
    any of them
}