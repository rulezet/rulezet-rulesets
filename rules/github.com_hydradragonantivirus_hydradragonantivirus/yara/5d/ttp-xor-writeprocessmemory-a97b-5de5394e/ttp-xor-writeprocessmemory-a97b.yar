rule TTP_XOR_WriteProcessMemory_a97b {
  strings:
    $key_a97b = { fe 09 [2] cc 2b [2] ca 1e [2] e4 1e [2] db 02 }

  condition:
    any of them
}