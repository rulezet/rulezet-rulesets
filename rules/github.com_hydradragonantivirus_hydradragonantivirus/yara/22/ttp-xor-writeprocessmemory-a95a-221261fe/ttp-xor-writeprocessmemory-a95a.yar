rule TTP_XOR_WriteProcessMemory_a95a {
  strings:
    $key_a95a = { fe 28 [2] cc 0a [2] ca 3f [2] e4 3f [2] db 23 }

  condition:
    any of them
}