rule TTP_XOR_WriteProcessMemory_9d64 {
  strings:
    $key_9d64 = { ca 16 [2] f8 34 [2] fe 01 [2] d0 01 [2] ef 1d }

  condition:
    any of them
}