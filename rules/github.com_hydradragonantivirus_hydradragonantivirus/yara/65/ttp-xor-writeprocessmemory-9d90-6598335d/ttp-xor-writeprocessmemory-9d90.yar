rule TTP_XOR_WriteProcessMemory_9d90 {
  strings:
    $key_9d90 = { ca e2 [2] f8 c0 [2] fe f5 [2] d0 f5 [2] ef e9 }

  condition:
    any of them
}