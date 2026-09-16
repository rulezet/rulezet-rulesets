rule TTP_XOR_WriteProcessMemory_9d2d {
  strings:
    $key_9d2d = { ca 5f [2] f8 7d [2] fe 48 [2] d0 48 [2] ef 54 }

  condition:
    any of them
}