rule TTP_XOR_WriteProcessMemory_a902 {
  strings:
    $key_a902 = { fe 70 [2] cc 52 [2] ca 67 [2] e4 67 [2] db 7b }

  condition:
    any of them
}