rule TTP_XOR_WriteProcessMemory_9d59 {
  strings:
    $key_9d59 = { ca 2b [2] f8 09 [2] fe 3c [2] d0 3c [2] ef 20 }

  condition:
    any of them
}