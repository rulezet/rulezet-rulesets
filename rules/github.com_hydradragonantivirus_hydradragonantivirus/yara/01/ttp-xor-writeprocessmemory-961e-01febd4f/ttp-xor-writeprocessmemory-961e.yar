rule TTP_XOR_WriteProcessMemory_961e {
  strings:
    $key_961e = { c1 6c [2] f3 4e [2] f5 7b [2] db 7b [2] e4 67 }

  condition:
    any of them
}