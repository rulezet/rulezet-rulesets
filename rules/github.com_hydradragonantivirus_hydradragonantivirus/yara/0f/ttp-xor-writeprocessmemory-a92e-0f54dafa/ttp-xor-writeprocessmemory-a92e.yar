rule TTP_XOR_WriteProcessMemory_a92e {
  strings:
    $key_a92e = { fe 5c [2] cc 7e [2] ca 4b [2] e4 4b [2] db 57 }

  condition:
    any of them
}