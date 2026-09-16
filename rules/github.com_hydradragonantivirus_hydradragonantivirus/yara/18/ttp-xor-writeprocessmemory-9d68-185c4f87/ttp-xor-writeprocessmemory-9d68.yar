rule TTP_XOR_WriteProcessMemory_9d68 {
  strings:
    $key_9d68 = { ca 1a [2] f8 38 [2] fe 0d [2] d0 0d [2] ef 11 }

  condition:
    any of them
}