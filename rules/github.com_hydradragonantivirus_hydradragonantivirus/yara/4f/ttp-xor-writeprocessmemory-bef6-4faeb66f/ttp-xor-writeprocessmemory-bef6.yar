rule TTP_XOR_WriteProcessMemory_bef6 {
  strings:
    $key_bef6 = { e9 84 [2] db a6 [2] dd 93 [2] f3 93 [2] cc 8f }

  condition:
    any of them
}