rule TTP_XOR_WriteProcessMemory_9d1f {
  strings:
    $key_9d1f = { ca 6d [2] f8 4f [2] fe 7a [2] d0 7a [2] ef 66 }

  condition:
    any of them
}