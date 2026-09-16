rule TTP_XOR_WriteProcessMemory_f017 {
  strings:
    $key_f017 = { a7 65 [2] 95 47 [2] 93 72 [2] bd 72 [2] 82 6e }

  condition:
    any of them
}