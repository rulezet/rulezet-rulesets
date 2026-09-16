rule TTP_XOR_WriteProcessMemory_9d70 {
  strings:
    $key_9d70 = { ca 02 [2] f8 20 [2] fe 15 [2] d0 15 [2] ef 09 }

  condition:
    any of them
}