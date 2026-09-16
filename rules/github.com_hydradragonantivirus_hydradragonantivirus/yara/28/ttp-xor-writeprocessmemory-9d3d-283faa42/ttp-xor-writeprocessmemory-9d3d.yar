rule TTP_XOR_WriteProcessMemory_9d3d {
  strings:
    $key_9d3d = { ca 4f [2] f8 6d [2] fe 58 [2] d0 58 [2] ef 44 }

  condition:
    any of them
}