rule TTP_XOR_WriteProcessMemory_965c {
  strings:
    $key_965c = { c1 2e [2] f3 0c [2] f5 39 [2] db 39 [2] e4 25 }

  condition:
    any of them
}