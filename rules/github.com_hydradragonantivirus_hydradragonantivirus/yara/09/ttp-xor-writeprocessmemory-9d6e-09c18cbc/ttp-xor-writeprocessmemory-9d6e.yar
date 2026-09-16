rule TTP_XOR_WriteProcessMemory_9d6e {
  strings:
    $key_9d6e = { ca 1c [2] f8 3e [2] fe 0b [2] d0 0b [2] ef 17 }

  condition:
    any of them
}