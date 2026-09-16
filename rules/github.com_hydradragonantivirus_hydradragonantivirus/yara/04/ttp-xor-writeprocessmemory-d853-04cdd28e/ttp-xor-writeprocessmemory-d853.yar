rule TTP_XOR_WriteProcessMemory_d853 {
  strings:
    $key_d853 = { 8f 21 [2] bd 03 [2] bb 36 [2] 95 36 [2] aa 2a }

  condition:
    any of them
}