rule TTP_XOR_WriteProcessMemory_a941 {
  strings:
    $key_a941 = { fe 33 [2] cc 11 [2] ca 24 [2] e4 24 [2] db 38 }

  condition:
    any of them
}