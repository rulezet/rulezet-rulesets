rule TTP_XOR_WriteProcessMemory_9d55 {
  strings:
    $key_9d55 = { ca 27 [2] f8 05 [2] fe 30 [2] d0 30 [2] ef 2c }

  condition:
    any of them
}