rule TTP_XOR_WriteProcessMemory_a910 {
  strings:
    $key_a910 = { fe 62 [2] cc 40 [2] ca 75 [2] e4 75 [2] db 69 }

  condition:
    any of them
}