rule TTP_XOR_WriteProcessMemory_9d6b {
  strings:
    $key_9d6b = { ca 19 [2] f8 3b [2] fe 0e [2] d0 0e [2] ef 12 }

  condition:
    any of them
}