rule TTP_XOR_WriteProcessMemory_9d7e {
  strings:
    $key_9d7e = { ca 0c [2] f8 2e [2] fe 1b [2] d0 1b [2] ef 07 }

  condition:
    any of them
}