rule TTP_XOR_WriteProcessMemory_d845 {
  strings:
    $key_d845 = { 8f 37 [2] bd 15 [2] bb 20 [2] 95 20 [2] aa 3c }

  condition:
    any of them
}