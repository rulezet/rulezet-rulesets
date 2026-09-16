rule TTP_XOR_WriteProcessMemory_bef9 {
  strings:
    $key_bef9 = { e9 8b [2] db a9 [2] dd 9c [2] f3 9c [2] cc 80 }

  condition:
    any of them
}