rule TTP_XOR_WriteProcessMemory_a939 {
  strings:
    $key_a939 = { fe 4b [2] cc 69 [2] ca 5c [2] e4 5c [2] db 40 }

  condition:
    any of them
}