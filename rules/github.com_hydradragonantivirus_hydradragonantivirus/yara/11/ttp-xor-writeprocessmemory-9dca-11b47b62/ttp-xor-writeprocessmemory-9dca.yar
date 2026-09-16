rule TTP_XOR_WriteProcessMemory_9dca {
  strings:
    $key_9dca = { ca b8 [2] f8 9a [2] fe af [2] d0 af [2] ef b3 }

  condition:
    any of them
}