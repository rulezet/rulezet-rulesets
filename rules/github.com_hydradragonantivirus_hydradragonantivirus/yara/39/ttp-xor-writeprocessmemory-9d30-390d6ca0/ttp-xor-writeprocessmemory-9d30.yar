rule TTP_XOR_WriteProcessMemory_9d30 {
  strings:
    $key_9d30 = { ca 42 [2] f8 60 [2] fe 55 [2] d0 55 [2] ef 49 }

  condition:
    any of them
}