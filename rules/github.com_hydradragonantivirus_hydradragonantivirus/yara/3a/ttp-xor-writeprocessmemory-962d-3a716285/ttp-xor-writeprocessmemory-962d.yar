rule TTP_XOR_WriteProcessMemory_962d {
  strings:
    $key_962d = { c1 5f [2] f3 7d [2] f5 48 [2] db 48 [2] e4 54 }

  condition:
    any of them
}