rule TTP_XOR_WriteProcessMemory_9dff {
  strings:
    $key_9dff = { ca 8d [2] f8 af [2] fe 9a [2] d0 9a [2] ef 86 }

  condition:
    any of them
}