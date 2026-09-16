rule TTP_XOR_WriteProcessMemory_9deb {
  strings:
    $key_9deb = { ca 99 [2] f8 bb [2] fe 8e [2] d0 8e [2] ef 92 }

  condition:
    any of them
}