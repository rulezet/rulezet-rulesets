rule TTP_XOR_WriteProcessMemory_9d23 {
  strings:
    $key_9d23 = { ca 51 [2] f8 73 [2] fe 46 [2] d0 46 [2] ef 5a }

  condition:
    any of them
}