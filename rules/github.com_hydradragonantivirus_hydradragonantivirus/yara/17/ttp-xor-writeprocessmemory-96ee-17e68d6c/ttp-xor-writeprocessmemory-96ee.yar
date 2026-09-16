rule TTP_XOR_WriteProcessMemory_96ee {
  strings:
    $key_96ee = { c1 9c [2] f3 be [2] f5 8b [2] db 8b [2] e4 97 }

  condition:
    any of them
}