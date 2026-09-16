rule TTP_XOR_WriteProcessMemory_9dc8 {
  strings:
    $key_9dc8 = { ca ba [2] f8 98 [2] fe ad [2] d0 ad [2] ef b1 }

  condition:
    any of them
}