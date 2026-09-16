rule TTP_XOR_WriteProcessMemory_a93c {
  strings:
    $key_a93c = { fe 4e [2] cc 6c [2] ca 59 [2] e4 59 [2] db 45 }

  condition:
    any of them
}