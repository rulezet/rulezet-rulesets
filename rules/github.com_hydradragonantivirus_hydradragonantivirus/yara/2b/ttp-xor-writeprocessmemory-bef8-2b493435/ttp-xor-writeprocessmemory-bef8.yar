rule TTP_XOR_WriteProcessMemory_bef8 {
  strings:
    $key_bef8 = { e9 8a [2] db a8 [2] dd 9d [2] f3 9d [2] cc 81 }

  condition:
    any of them
}