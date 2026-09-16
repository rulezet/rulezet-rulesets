rule TTP_XOR_WriteProcessMemory_a90f {
  strings:
    $key_a90f = { fe 7d [2] cc 5f [2] ca 6a [2] e4 6a [2] db 76 }

  condition:
    any of them
}