rule TTP_XOR_WriteProcessMemory_963d {
  strings:
    $key_963d = { c1 4f [2] f3 6d [2] f5 58 [2] db 58 [2] e4 44 }

  condition:
    any of them
}