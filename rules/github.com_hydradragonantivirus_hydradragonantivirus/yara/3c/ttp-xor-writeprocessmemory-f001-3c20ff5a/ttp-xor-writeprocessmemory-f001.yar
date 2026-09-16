rule TTP_XOR_WriteProcessMemory_f001 {
  strings:
    $key_f001 = { a7 73 [2] 95 51 [2] 93 64 [2] bd 64 [2] 82 78 }

  condition:
    any of them
}