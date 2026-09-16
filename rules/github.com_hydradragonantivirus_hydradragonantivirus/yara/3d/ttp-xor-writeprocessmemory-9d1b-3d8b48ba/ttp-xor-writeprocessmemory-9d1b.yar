rule TTP_XOR_WriteProcessMemory_9d1b {
  strings:
    $key_9d1b = { ca 69 [2] f8 4b [2] fe 7e [2] d0 7e [2] ef 62 }

  condition:
    any of them
}