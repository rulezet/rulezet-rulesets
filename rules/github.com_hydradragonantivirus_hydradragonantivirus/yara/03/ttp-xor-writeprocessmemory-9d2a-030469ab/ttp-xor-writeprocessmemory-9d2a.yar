rule TTP_XOR_WriteProcessMemory_9d2a {
  strings:
    $key_9d2a = { ca 58 [2] f8 7a [2] fe 4f [2] d0 4f [2] ef 53 }

  condition:
    any of them
}