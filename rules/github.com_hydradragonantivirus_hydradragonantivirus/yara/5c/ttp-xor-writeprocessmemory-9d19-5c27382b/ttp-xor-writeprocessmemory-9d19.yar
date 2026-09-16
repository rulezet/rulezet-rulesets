rule TTP_XOR_WriteProcessMemory_9d19 {
  strings:
    $key_9d19 = { ca 6b [2] f8 49 [2] fe 7c [2] d0 7c [2] ef 60 }

  condition:
    any of them
}