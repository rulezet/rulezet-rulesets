rule TTP_XOR_WriteProcessMemory_9d48 {
  strings:
    $key_9d48 = { ca 3a [2] f8 18 [2] fe 2d [2] d0 2d [2] ef 31 }

  condition:
    any of them
}