rule TTP_XOR_WriteProcessMemory_9df9 {
  strings:
    $key_9df9 = { ca 8b [2] f8 a9 [2] fe 9c [2] d0 9c [2] ef 80 }

  condition:
    any of them
}