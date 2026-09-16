rule TTP_XOR_WriteProcessMemory_a9fc {
  strings:
    $key_a9fc = { fe 8e [2] cc ac [2] ca 99 [2] e4 99 [2] db 85 }

  condition:
    any of them
}