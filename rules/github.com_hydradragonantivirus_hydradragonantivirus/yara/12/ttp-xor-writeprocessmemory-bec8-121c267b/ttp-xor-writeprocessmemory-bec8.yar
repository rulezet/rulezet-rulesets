rule TTP_XOR_WriteProcessMemory_bec8 {
  strings:
    $key_bec8 = { e9 ba [2] db 98 [2] dd ad [2] f3 ad [2] cc b1 }

  condition:
    any of them
}