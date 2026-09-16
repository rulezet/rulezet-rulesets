rule TTP_XOR_WriteProcessMemory_a9f0 {
  strings:
    $key_a9f0 = { fe 82 [2] cc a0 [2] ca 95 [2] e4 95 [2] db 89 }

  condition:
    any of them
}