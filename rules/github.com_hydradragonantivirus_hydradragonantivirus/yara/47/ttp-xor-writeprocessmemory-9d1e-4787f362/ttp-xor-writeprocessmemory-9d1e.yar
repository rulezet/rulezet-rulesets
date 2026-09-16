rule TTP_XOR_WriteProcessMemory_9d1e {
  strings:
    $key_9d1e = { ca 6c [2] f8 4e [2] fe 7b [2] d0 7b [2] ef 67 }

  condition:
    any of them
}