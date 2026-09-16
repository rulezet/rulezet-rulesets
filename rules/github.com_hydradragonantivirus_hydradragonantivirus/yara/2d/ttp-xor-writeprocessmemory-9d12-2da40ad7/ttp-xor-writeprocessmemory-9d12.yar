rule TTP_XOR_WriteProcessMemory_9d12 {
  strings:
    $key_9d12 = { ca 60 [2] f8 42 [2] fe 77 [2] d0 77 [2] ef 6b }

  condition:
    any of them
}