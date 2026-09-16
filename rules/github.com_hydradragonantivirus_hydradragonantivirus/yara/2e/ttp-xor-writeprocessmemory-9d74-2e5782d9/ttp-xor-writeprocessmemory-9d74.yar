rule TTP_XOR_WriteProcessMemory_9d74 {
  strings:
    $key_9d74 = { ca 06 [2] f8 24 [2] fe 11 [2] d0 11 [2] ef 0d }

  condition:
    any of them
}