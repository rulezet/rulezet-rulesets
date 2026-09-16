rule TTP_XOR_WriteProcessMemory_9d0c {
  strings:
    $key_9d0c = { ca 7e [2] f8 5c [2] fe 69 [2] d0 69 [2] ef 75 }

  condition:
    any of them
}