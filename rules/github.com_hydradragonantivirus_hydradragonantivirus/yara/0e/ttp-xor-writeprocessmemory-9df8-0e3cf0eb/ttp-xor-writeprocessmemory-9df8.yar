rule TTP_XOR_WriteProcessMemory_9df8 {
  strings:
    $key_9df8 = { ca 8a [2] f8 a8 [2] fe 9d [2] d0 9d [2] ef 81 }

  condition:
    any of them
}