rule TTP_XOR_WriteProcessMemory_a908 {
  strings:
    $key_a908 = { fe 7a [2] cc 58 [2] ca 6d [2] e4 6d [2] db 71 }

  condition:
    any of them
}