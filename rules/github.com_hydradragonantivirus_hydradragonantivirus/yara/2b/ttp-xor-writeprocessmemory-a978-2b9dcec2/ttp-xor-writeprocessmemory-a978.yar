rule TTP_XOR_WriteProcessMemory_a978 {
  strings:
    $key_a978 = { fe 0a [2] cc 28 [2] ca 1d [2] e4 1d [2] db 01 }

  condition:
    any of them
}