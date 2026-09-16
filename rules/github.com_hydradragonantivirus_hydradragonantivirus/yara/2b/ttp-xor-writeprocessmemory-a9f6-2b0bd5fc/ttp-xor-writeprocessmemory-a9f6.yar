rule TTP_XOR_WriteProcessMemory_a9f6 {
  strings:
    $key_a9f6 = { fe 84 [2] cc a6 [2] ca 93 [2] e4 93 [2] db 8f }

  condition:
    any of them
}