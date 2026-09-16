rule TTP_XOR_WriteProcessMemory_9d7c {
  strings:
    $key_9d7c = { ca 0e [2] f8 2c [2] fe 19 [2] d0 19 [2] ef 05 }

  condition:
    any of them
}