rule TTP_XOR_WriteProcessMemory_becc {
  strings:
    $key_becc = { e9 be [2] db 9c [2] dd a9 [2] f3 a9 [2] cc b5 }

  condition:
    any of them
}