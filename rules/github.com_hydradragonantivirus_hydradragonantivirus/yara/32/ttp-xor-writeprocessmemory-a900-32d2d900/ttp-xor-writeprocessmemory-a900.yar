rule TTP_XOR_WriteProcessMemory_a900 {
  strings:
    $key_a900 = { fe 72 [2] cc 50 [2] ca 65 [2] e4 65 [2] db 79 }

  condition:
    any of them
}