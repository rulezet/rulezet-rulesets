rule TTP_XOR_WriteProcessMemory_f027 {
  strings:
    $key_f027 = { a7 55 [2] 95 77 [2] 93 42 [2] bd 42 [2] 82 5e }

  condition:
    any of them
}