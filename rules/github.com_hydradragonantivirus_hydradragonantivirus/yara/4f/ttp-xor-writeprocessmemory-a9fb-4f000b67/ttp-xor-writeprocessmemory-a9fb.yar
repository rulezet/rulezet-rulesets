rule TTP_XOR_WriteProcessMemory_a9fb {
  strings:
    $key_a9fb = { fe 89 [2] cc ab [2] ca 9e [2] e4 9e [2] db 82 }

  condition:
    any of them
}