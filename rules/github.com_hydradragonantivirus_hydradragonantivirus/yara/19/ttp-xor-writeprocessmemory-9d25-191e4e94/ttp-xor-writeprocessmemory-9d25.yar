rule TTP_XOR_WriteProcessMemory_9d25 {
  strings:
    $key_9d25 = { ca 57 [2] f8 75 [2] fe 40 [2] d0 40 [2] ef 5c }

  condition:
    any of them
}