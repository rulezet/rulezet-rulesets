rule TTP_XOR_WriteProcessMemory_a921 {
  strings:
    $key_a921 = { fe 53 [2] cc 71 [2] ca 44 [2] e4 44 [2] db 58 }

  condition:
    any of them
}