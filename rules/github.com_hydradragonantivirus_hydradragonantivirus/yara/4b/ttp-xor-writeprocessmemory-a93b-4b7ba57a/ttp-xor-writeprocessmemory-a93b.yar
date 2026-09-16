rule TTP_XOR_WriteProcessMemory_a93b {
  strings:
    $key_a93b = { fe 49 [2] cc 6b [2] ca 5e [2] e4 5e [2] db 42 }

  condition:
    any of them
}