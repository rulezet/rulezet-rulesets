rule TTP_XOR_WriteProcessMemory_a948 {
  strings:
    $key_a948 = { fe 3a [2] cc 18 [2] ca 2d [2] e4 2d [2] db 31 }

  condition:
    any of them
}