rule TTP_XOR_WriteProcessMemory_a9e0 {
  strings:
    $key_a9e0 = { fe 92 [2] cc b0 [2] ca 85 [2] e4 85 [2] db 99 }

  condition:
    any of them
}