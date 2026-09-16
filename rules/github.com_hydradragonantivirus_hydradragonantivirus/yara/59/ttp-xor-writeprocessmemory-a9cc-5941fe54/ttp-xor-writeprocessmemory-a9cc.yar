rule TTP_XOR_WriteProcessMemory_a9cc {
  strings:
    $key_a9cc = { fe be [2] cc 9c [2] ca a9 [2] e4 a9 [2] db b5 }

  condition:
    any of them
}