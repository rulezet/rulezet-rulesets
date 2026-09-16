rule TTP_XOR_WriteProcessMemory_bef0 {
  strings:
    $key_bef0 = { e9 82 [2] db a0 [2] dd 95 [2] f3 95 [2] cc 89 }

  condition:
    any of them
}