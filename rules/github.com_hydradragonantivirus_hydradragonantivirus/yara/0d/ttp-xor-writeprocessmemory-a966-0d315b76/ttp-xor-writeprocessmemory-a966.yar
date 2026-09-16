rule TTP_XOR_WriteProcessMemory_a966 {
  strings:
    $key_a966 = { fe 14 [2] cc 36 [2] ca 03 [2] e4 03 [2] db 1f }

  condition:
    any of them
}