rule TTP_XOR_WriteProcessMemory_f047 {
  strings:
    $key_f047 = { a7 35 [2] 95 17 [2] 93 22 [2] bd 22 [2] 82 3e }

  condition:
    any of them
}