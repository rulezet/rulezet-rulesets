rule TTP_XOR_WriteProcessMemory_a950 {
  strings:
    $key_a950 = { fe 22 [2] cc 00 [2] ca 35 [2] e4 35 [2] db 29 }

  condition:
    any of them
}