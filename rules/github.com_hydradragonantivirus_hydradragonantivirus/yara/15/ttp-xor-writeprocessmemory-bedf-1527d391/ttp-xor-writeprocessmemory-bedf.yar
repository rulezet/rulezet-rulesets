rule TTP_XOR_WriteProcessMemory_bedf {
  strings:
    $key_bedf = { e9 ad [2] db 8f [2] dd ba [2] f3 ba [2] cc a6 }

  condition:
    any of them
}