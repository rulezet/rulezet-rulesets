rule TTP_XOR_WriteProcessMemory_962e {
  strings:
    $key_962e = { c1 5c [2] f3 7e [2] f5 4b [2] db 4b [2] e4 57 }

  condition:
    any of them
}