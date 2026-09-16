rule TTP_XOR_WriteProcessMemory_a972 {
  strings:
    $key_a972 = { fe 00 [2] cc 22 [2] ca 17 [2] e4 17 [2] db 0b }

  condition:
    any of them
}