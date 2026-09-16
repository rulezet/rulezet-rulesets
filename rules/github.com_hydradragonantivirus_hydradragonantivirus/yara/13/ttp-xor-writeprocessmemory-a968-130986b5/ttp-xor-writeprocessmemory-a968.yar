rule TTP_XOR_WriteProcessMemory_a968 {
  strings:
    $key_a968 = { fe 1a [2] cc 38 [2] ca 0d [2] e4 0d [2] db 11 }

  condition:
    any of them
}