rule TTP_XOR_WriteProcessMemory_f024 {
  strings:
    $key_f024 = { a7 56 [2] 95 74 [2] 93 41 [2] bd 41 [2] 82 5d }

  condition:
    any of them
}