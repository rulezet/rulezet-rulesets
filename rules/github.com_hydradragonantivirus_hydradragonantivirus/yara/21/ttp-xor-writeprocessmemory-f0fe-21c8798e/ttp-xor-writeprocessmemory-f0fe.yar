rule TTP_XOR_WriteProcessMemory_f0fe {
  strings:
    $key_f0fe = { a7 8c [2] 95 ae [2] 93 9b [2] bd 9b [2] 82 87 }

  condition:
    any of them
}