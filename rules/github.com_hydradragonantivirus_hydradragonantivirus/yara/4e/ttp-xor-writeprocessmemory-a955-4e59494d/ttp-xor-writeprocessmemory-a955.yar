rule TTP_XOR_WriteProcessMemory_a955 {
  strings:
    $key_a955 = { fe 27 [2] cc 05 [2] ca 30 [2] e4 30 [2] db 2c }

  condition:
    any of them
}