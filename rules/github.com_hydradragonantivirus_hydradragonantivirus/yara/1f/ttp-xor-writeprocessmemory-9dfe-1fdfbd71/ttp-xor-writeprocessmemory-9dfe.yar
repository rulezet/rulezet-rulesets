rule TTP_XOR_WriteProcessMemory_9dfe {
  strings:
    $key_9dfe = { ca 8c [2] f8 ae [2] fe 9b [2] d0 9b [2] ef 87 }

  condition:
    any of them
}