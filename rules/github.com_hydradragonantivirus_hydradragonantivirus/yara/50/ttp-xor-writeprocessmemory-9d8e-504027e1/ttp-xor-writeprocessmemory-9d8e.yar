rule TTP_XOR_WriteProcessMemory_9d8e {
  strings:
    $key_9d8e = { ca fc [2] f8 de [2] fe eb [2] d0 eb [2] ef f7 }

  condition:
    any of them
}