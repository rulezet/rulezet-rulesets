rule TTP_XOR_WriteProcessMemory_9d51 {
  strings:
    $key_9d51 = { ca 23 [2] f8 01 [2] fe 34 [2] d0 34 [2] ef 28 }

  condition:
    any of them
}