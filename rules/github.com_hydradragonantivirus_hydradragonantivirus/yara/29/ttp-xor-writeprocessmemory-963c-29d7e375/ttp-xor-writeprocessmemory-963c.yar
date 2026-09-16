rule TTP_XOR_WriteProcessMemory_963c {
  strings:
    $key_963c = { c1 4e [2] f3 6c [2] f5 59 [2] db 59 [2] e4 45 }

  condition:
    any of them
}