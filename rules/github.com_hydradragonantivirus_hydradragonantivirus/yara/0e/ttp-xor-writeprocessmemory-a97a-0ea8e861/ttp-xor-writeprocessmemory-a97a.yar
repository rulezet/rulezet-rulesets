rule TTP_XOR_WriteProcessMemory_a97a {
  strings:
    $key_a97a = { fe 08 [2] cc 2a [2] ca 1f [2] e4 1f [2] db 03 }

  condition:
    any of them
}