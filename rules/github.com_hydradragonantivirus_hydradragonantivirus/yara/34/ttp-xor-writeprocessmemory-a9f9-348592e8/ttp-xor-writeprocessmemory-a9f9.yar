rule TTP_XOR_WriteProcessMemory_a9f9 {
  strings:
    $key_a9f9 = { fe 8b [2] cc a9 [2] ca 9c [2] e4 9c [2] db 80 }

  condition:
    any of them
}