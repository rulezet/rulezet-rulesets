rule TTP_XOR_WriteProcessMemory_a97e {
  strings:
    $key_a97e = { fe 0c [2] cc 2e [2] ca 1b [2] e4 1b [2] db 07 }

  condition:
    any of them
}