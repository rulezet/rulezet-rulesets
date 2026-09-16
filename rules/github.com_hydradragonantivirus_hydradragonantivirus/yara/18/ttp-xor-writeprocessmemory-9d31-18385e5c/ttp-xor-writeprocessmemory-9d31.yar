rule TTP_XOR_WriteProcessMemory_9d31 {
  strings:
    $key_9d31 = { ca 43 [2] f8 61 [2] fe 54 [2] d0 54 [2] ef 48 }

  condition:
    any of them
}