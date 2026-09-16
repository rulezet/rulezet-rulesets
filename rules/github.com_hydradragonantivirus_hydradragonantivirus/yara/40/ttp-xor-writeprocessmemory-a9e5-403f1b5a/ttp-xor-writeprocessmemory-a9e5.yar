rule TTP_XOR_WriteProcessMemory_a9e5 {
  strings:
    $key_a9e5 = { fe 97 [2] cc b5 [2] ca 80 [2] e4 80 [2] db 9c }

  condition:
    any of them
}