rule TTP_XOR_WriteProcessMemory_bef2 {
  strings:
    $key_bef2 = { e9 80 [2] db a2 [2] dd 97 [2] f3 97 [2] cc 8b }

  condition:
    any of them
}