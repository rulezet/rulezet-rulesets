rule TTP_XOR_WriteProcessMemory_beca {
  strings:
    $key_beca = { e9 b8 [2] db 9a [2] dd af [2] f3 af [2] cc b3 }

  condition:
    any of them
}