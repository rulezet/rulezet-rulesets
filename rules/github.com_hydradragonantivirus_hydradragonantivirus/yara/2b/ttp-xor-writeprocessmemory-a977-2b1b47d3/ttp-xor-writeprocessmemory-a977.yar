rule TTP_XOR_WriteProcessMemory_a977 {
  strings:
    $key_a977 = { fe 05 [2] cc 27 [2] ca 12 [2] e4 12 [2] db 0e }

  condition:
    any of them
}