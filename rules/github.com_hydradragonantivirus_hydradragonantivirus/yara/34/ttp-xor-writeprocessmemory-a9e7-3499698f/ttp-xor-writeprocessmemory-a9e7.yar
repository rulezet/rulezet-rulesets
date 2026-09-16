rule TTP_XOR_WriteProcessMemory_a9e7 {
  strings:
    $key_a9e7 = { fe 95 [2] cc b7 [2] ca 82 [2] e4 82 [2] db 9e }

  condition:
    any of them
}