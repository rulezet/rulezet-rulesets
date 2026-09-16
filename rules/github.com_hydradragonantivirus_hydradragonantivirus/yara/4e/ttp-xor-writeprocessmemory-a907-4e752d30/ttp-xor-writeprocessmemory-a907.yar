rule TTP_XOR_WriteProcessMemory_a907 {
  strings:
    $key_a907 = { fe 75 [2] cc 57 [2] ca 62 [2] e4 62 [2] db 7e }

  condition:
    any of them
}