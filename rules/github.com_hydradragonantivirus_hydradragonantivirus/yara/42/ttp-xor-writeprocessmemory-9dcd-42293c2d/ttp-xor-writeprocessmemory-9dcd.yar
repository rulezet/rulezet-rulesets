rule TTP_XOR_WriteProcessMemory_9dcd {
  strings:
    $key_9dcd = { ca bf [2] f8 9d [2] fe a8 [2] d0 a8 [2] ef b4 }

  condition:
    any of them
}