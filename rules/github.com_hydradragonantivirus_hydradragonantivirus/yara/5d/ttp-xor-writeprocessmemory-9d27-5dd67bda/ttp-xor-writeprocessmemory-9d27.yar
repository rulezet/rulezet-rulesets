rule TTP_XOR_WriteProcessMemory_9d27 {
  strings:
    $key_9d27 = { ca 55 [2] f8 77 [2] fe 42 [2] d0 42 [2] ef 5e }

  condition:
    any of them
}