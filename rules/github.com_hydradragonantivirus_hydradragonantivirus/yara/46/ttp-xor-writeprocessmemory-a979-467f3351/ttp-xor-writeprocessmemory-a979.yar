rule TTP_XOR_WriteProcessMemory_a979 {
  strings:
    $key_a979 = { fe 0b [2] cc 29 [2] ca 1c [2] e4 1c [2] db 00 }

  condition:
    any of them
}