rule TTP_XOR_WriteProcessMemory_960d {
  strings:
    $key_960d = { c1 7f [2] f3 5d [2] f5 68 [2] db 68 [2] e4 74 }

  condition:
    any of them
}