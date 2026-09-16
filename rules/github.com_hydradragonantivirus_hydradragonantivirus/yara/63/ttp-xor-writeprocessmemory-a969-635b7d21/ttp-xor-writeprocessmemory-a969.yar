rule TTP_XOR_WriteProcessMemory_a969 {
  strings:
    $key_a969 = { fe 1b [2] cc 39 [2] ca 0c [2] e4 0c [2] db 10 }

  condition:
    any of them
}