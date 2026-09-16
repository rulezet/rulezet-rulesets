rule TTP_XOR_WriteProcessMemory_a909 {
  strings:
    $key_a909 = { fe 7b [2] cc 59 [2] ca 6c [2] e4 6c [2] db 70 }

  condition:
    any of them
}