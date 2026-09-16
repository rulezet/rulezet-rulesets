rule TTP_XOR_WriteProcessMemory_a945 {
  strings:
    $key_a945 = { fe 37 [2] cc 15 [2] ca 20 [2] e4 20 [2] db 3c }

  condition:
    any of them
}