rule TTP_XOR_WriteProcessMemory_a942 {
  strings:
    $key_a942 = { fe 30 [2] cc 12 [2] ca 27 [2] e4 27 [2] db 3b }

  condition:
    any of them
}