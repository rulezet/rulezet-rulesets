rule TTP_XOR_WriteProcessMemory_f015 {
  strings:
    $key_f015 = { a7 67 [2] 95 45 [2] 93 70 [2] bd 70 [2] 82 6c }

  condition:
    any of them
}