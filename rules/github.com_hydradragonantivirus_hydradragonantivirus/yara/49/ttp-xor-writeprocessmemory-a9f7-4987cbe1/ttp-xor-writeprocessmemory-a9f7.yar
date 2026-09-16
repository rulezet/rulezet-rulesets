rule TTP_XOR_WriteProcessMemory_a9f7 {
  strings:
    $key_a9f7 = { fe 85 [2] cc a7 [2] ca 92 [2] e4 92 [2] db 8e }

  condition:
    any of them
}