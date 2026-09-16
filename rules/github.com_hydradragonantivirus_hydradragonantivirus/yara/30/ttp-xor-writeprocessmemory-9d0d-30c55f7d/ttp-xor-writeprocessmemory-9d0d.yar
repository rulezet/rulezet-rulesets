rule TTP_XOR_WriteProcessMemory_9d0d {
  strings:
    $key_9d0d = { ca 7f [2] f8 5d [2] fe 68 [2] d0 68 [2] ef 74 }

  condition:
    any of them
}