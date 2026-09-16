rule TTP_XOR_WriteProcessMemory_d855 {
  strings:
    $key_d855 = { 8f 27 [2] bd 05 [2] bb 30 [2] 95 30 [2] aa 2c }

  condition:
    any of them
}