rule TTP_XOR_WriteProcessMemory_a94d {
  strings:
    $key_a94d = { fe 3f [2] cc 1d [2] ca 28 [2] e4 28 [2] db 34 }

  condition:
    any of them
}