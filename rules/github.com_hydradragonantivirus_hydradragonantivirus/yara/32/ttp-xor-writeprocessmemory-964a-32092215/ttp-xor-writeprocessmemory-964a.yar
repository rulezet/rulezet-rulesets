rule TTP_XOR_WriteProcessMemory_964a {
  strings:
    $key_964a = { c1 38 [2] f3 1a [2] f5 2f [2] db 2f [2] e4 33 }

  condition:
    any of them
}