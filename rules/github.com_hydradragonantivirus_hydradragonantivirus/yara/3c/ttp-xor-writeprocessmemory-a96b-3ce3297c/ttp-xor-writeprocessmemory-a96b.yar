rule TTP_XOR_WriteProcessMemory_a96b {
  strings:
    $key_a96b = { fe 19 [2] cc 3b [2] ca 0e [2] e4 0e [2] db 12 }

  condition:
    any of them
}