rule TTP_XOR_WriteProcessMemory_a962 {
  strings:
    $key_a962 = { fe 10 [2] cc 32 [2] ca 07 [2] e4 07 [2] db 1b }

  condition:
    any of them
}