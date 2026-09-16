rule TTP_XOR_WriteProcessMemory_9d1c {
  strings:
    $key_9d1c = { ca 6e [2] f8 4c [2] fe 79 [2] d0 79 [2] ef 65 }

  condition:
    any of them
}