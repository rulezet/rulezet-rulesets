rule TTP_XOR_WriteProcessMemory_9d24 {
  strings:
    $key_9d24 = { ca 56 [2] f8 74 [2] fe 41 [2] d0 41 [2] ef 5d }

  condition:
    any of them
}