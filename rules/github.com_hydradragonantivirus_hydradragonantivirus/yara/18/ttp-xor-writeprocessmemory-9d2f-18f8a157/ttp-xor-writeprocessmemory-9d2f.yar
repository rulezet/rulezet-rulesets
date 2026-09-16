rule TTP_XOR_WriteProcessMemory_9d2f {
  strings:
    $key_9d2f = { ca 5d [2] f8 7f [2] fe 4a [2] d0 4a [2] ef 56 }

  condition:
    any of them
}