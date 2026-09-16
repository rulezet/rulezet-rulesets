rule TTP_XOR_WriteProcessMemory_bedb {
  strings:
    $key_bedb = { e9 a9 [2] db 8b [2] dd be [2] f3 be [2] cc a2 }

  condition:
    any of them
}