rule TTP_XOR_WriteProcessMemory_9d5c {
  strings:
    $key_9d5c = { ca 2e [2] f8 0c [2] fe 39 [2] d0 39 [2] ef 25 }

  condition:
    any of them
}