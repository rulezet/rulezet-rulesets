rule TTP_XOR_WriteProcessMemory_a93e {
  strings:
    $key_a93e = { fe 4c [2] cc 6e [2] ca 5b [2] e4 5b [2] db 47 }

  condition:
    any of them
}