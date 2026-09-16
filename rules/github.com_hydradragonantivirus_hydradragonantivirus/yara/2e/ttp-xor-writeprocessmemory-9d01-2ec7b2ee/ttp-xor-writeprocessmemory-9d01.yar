rule TTP_XOR_WriteProcessMemory_9d01 {
  strings:
    $key_9d01 = { ca 73 [2] f8 51 [2] fe 64 [2] d0 64 [2] ef 78 }

  condition:
    any of them
}