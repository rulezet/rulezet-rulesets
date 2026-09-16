rule TTP_XOR_WriteProcessMemory_a975 {
  strings:
    $key_a975 = { fe 07 [2] cc 25 [2] ca 10 [2] e4 10 [2] db 0c }

  condition:
    any of them
}