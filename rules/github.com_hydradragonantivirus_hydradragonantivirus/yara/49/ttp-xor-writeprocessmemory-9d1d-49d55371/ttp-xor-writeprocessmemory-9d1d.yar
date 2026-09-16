rule TTP_XOR_WriteProcessMemory_9d1d {
  strings:
    $key_9d1d = { ca 6f [2] f8 4d [2] fe 78 [2] d0 78 [2] ef 64 }

  condition:
    any of them
}