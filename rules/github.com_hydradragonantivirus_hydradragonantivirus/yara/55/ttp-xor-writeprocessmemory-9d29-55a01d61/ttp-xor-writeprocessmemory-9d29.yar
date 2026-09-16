rule TTP_XOR_WriteProcessMemory_9d29 {
  strings:
    $key_9d29 = { ca 5b [2] f8 79 [2] fe 4c [2] d0 4c [2] ef 50 }

  condition:
    any of them
}