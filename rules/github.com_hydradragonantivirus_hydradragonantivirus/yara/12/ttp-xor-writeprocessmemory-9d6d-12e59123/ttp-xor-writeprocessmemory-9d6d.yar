rule TTP_XOR_WriteProcessMemory_9d6d {
  strings:
    $key_9d6d = { ca 1f [2] f8 3d [2] fe 08 [2] d0 08 [2] ef 14 }

  condition:
    any of them
}