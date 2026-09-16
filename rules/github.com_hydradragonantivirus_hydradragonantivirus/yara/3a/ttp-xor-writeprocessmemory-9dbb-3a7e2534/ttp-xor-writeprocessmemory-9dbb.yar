rule TTP_XOR_WriteProcessMemory_9dbb {
  strings:
    $key_9dbb = { ca c9 [2] f8 eb [2] fe de [2] d0 de [2] ef c2 }

  condition:
    any of them
}