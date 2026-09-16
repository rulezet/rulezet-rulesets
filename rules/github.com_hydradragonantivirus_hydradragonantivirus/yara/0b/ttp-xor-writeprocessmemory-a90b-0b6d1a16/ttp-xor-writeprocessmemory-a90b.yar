rule TTP_XOR_WriteProcessMemory_a90b {
  strings:
    $key_a90b = { fe 79 [2] cc 5b [2] ca 6e [2] e4 6e [2] db 72 }

  condition:
    any of them
}