rule TTP_XOR_WriteProcessMemory_9dbe {
  strings:
    $key_9dbe = { ca cc [2] f8 ee [2] fe db [2] d0 db [2] ef c7 }

  condition:
    any of them
}