rule TTP_XOR_WriteProcessMemory_bec6 {
  strings:
    $key_bec6 = { e9 b4 [2] db 96 [2] dd a3 [2] f3 a3 [2] cc bf }

  condition:
    any of them
}