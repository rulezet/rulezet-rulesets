rule TTP_XOR_WriteProcessMemory_965d {
  strings:
    $key_965d = { c1 2f [2] f3 0d [2] f5 38 [2] db 38 [2] e4 24 }

  condition:
    any of them
}