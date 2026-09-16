rule TTP_XOR_WriteProcessMemory_9659 {
  strings:
    $key_9659 = { c1 2b [2] f3 09 [2] f5 3c [2] db 3c [2] e4 20 }

  condition:
    any of them
}