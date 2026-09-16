rule TTP_XOR_WriteProcessMemory_9d7b {
  strings:
    $key_9d7b = { ca 09 [2] f8 2b [2] fe 1e [2] d0 1e [2] ef 02 }

  condition:
    any of them
}