rule TTP_XOR_WriteProcessMemory_bedc {
  strings:
    $key_bedc = { e9 ae [2] db 8c [2] dd b9 [2] f3 b9 [2] cc a5 }

  condition:
    any of them
}