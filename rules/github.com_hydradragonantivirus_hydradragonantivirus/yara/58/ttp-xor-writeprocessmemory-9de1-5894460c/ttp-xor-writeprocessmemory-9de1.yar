rule TTP_XOR_WriteProcessMemory_9de1 {
  strings:
    $key_9de1 = { ca 93 [2] f8 b1 [2] fe 84 [2] d0 84 [2] ef 98 }

  condition:
    any of them
}