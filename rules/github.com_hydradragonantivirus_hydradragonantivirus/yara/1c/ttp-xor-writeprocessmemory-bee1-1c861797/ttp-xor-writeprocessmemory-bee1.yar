rule TTP_XOR_WriteProcessMemory_bee1 {
  strings:
    $key_bee1 = { e9 93 [2] db b1 [2] dd 84 [2] f3 84 [2] cc 98 }

  condition:
    any of them
}