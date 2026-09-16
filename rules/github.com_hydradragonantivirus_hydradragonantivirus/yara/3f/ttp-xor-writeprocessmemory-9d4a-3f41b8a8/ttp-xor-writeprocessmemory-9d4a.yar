rule TTP_XOR_WriteProcessMemory_9d4a {
  strings:
    $key_9d4a = { ca 38 [2] f8 1a [2] fe 2f [2] d0 2f [2] ef 33 }

  condition:
    any of them
}