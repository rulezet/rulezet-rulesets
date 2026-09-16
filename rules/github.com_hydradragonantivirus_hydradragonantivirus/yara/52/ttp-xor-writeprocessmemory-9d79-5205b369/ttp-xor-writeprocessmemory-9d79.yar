rule TTP_XOR_WriteProcessMemory_9d79 {
  strings:
    $key_9d79 = { ca 0b [2] f8 29 [2] fe 1c [2] d0 1c [2] ef 00 }

  condition:
    any of them
}