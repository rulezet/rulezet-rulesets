rule TTP_XOR_WriteProcessMemory_815b {
  strings:
    $key_815b = { d6 29 [2] e4 0b [2] e2 3e [2] cc 3e [2] f3 22 }

  condition:
    any of them
}