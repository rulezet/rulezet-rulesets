rule TTP_XOR_WriteProcessMemory_9dfd {
  strings:
    $key_9dfd = { ca 8f [2] f8 ad [2] fe 98 [2] d0 98 [2] ef 84 }

  condition:
    any of them
}