rule TTP_XOR_WriteProcessMemory_9d20 {
  strings:
    $key_9d20 = { ca 52 [2] f8 70 [2] fe 45 [2] d0 45 [2] ef 59 }

  condition:
    any of them
}