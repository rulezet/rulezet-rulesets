rule TTP_XOR_WriteProcessMemory_a97c {
  strings:
    $key_a97c = { fe 0e [2] cc 2c [2] ca 19 [2] e4 19 [2] db 05 }

  condition:
    any of them
}