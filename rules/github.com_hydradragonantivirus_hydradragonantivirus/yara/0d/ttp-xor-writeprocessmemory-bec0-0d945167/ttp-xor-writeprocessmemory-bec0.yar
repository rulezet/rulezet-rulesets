rule TTP_XOR_WriteProcessMemory_bec0 {
  strings:
    $key_bec0 = { e9 b2 [2] db 90 [2] dd a5 [2] f3 a5 [2] cc b9 }

  condition:
    any of them
}