rule TTP_XOR_WriteProcessMemory_963f {
  strings:
    $key_963f = { c1 4d [2] f3 6f [2] f5 5a [2] db 5a [2] e4 46 }

  condition:
    any of them
}