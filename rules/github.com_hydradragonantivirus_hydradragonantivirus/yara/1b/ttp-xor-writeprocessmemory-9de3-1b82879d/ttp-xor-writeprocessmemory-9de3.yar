rule TTP_XOR_WriteProcessMemory_9de3 {
  strings:
    $key_9de3 = { ca 91 [2] f8 b3 [2] fe 86 [2] d0 86 [2] ef 9a }

  condition:
    any of them
}