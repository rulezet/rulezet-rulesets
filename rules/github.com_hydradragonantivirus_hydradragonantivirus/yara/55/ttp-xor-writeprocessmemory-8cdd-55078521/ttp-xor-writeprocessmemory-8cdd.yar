rule TTP_XOR_WriteProcessMemory_8cdd {
  strings:
    $key_8cdd = { db af [2] e9 8d [2] ef b8 [2] c1 b8 [2] fe a4 }

  condition:
    any of them
}