rule TTP_XOR_WriteProcessMemory_9d45 {
  strings:
    $key_9d45 = { ca 37 [2] f8 15 [2] fe 20 [2] d0 20 [2] ef 3c }

  condition:
    any of them
}