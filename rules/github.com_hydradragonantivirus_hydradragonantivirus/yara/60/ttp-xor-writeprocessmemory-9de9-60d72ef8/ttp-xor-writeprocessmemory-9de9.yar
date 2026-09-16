rule TTP_XOR_WriteProcessMemory_9de9 {
  strings:
    $key_9de9 = { ca 9b [2] f8 b9 [2] fe 8c [2] d0 8c [2] ef 90 }

  condition:
    any of them
}