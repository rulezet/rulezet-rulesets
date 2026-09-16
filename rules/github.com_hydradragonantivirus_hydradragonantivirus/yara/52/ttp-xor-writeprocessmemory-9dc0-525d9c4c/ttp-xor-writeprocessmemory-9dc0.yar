rule TTP_XOR_WriteProcessMemory_9dc0 {
  strings:
    $key_9dc0 = { ca b2 [2] f8 90 [2] fe a5 [2] d0 a5 [2] ef b9 }

  condition:
    any of them
}