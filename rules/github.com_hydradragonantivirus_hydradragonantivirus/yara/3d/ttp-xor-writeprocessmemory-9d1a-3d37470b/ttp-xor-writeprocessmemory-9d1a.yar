rule TTP_XOR_WriteProcessMemory_9d1a {
  strings:
    $key_9d1a = { ca 68 [2] f8 4a [2] fe 7f [2] d0 7f [2] ef 63 }

  condition:
    any of them
}