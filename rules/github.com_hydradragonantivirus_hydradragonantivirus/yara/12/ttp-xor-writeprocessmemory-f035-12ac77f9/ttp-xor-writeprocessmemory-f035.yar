rule TTP_XOR_WriteProcessMemory_f035 {
  strings:
    $key_f035 = { a7 47 [2] 95 65 [2] 93 50 [2] bd 50 [2] 82 4c }

  condition:
    any of them
}