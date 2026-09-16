rule TTP_XOR_WriteProcessMemory_bef1 {
  strings:
    $key_bef1 = { e9 83 [2] db a1 [2] dd 94 [2] f3 94 [2] cc 88 }

  condition:
    any of them
}