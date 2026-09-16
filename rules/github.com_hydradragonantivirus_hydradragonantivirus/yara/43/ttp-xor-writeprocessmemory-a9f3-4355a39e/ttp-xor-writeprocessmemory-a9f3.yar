rule TTP_XOR_WriteProcessMemory_a9f3 {
  strings:
    $key_a9f3 = { fe 81 [2] cc a3 [2] ca 96 [2] e4 96 [2] db 8a }

  condition:
    any of them
}