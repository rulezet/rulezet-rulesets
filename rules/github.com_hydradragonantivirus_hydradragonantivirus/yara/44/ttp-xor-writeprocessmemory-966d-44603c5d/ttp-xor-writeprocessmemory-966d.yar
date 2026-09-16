rule TTP_XOR_WriteProcessMemory_966d {
  strings:
    $key_966d = { c1 1f [2] f3 3d [2] f5 08 [2] db 08 [2] e4 14 }

  condition:
    any of them
}