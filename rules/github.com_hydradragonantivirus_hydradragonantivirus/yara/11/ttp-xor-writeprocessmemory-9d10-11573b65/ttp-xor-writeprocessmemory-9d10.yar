rule TTP_XOR_WriteProcessMemory_9d10 {
  strings:
    $key_9d10 = { ca 62 [2] f8 40 [2] fe 75 [2] d0 75 [2] ef 69 }

  condition:
    any of them
}