rule TTP_XOR_WriteProcessMemory_9d61 {
  strings:
    $key_9d61 = { ca 13 [2] f8 31 [2] fe 04 [2] d0 04 [2] ef 18 }

  condition:
    any of them
}