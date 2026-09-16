rule TTP_XOR_WriteProcessMemory_bee8 {
  strings:
    $key_bee8 = { e9 9a [2] db b8 [2] dd 8d [2] f3 8d [2] cc 91 }

  condition:
    any of them
}