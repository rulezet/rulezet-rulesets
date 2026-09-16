rule TTP_XOR_WriteProcessMemory_d841 {
  strings:
    $key_d841 = { 8f 33 [2] bd 11 [2] bb 24 [2] 95 24 [2] aa 38 }

  condition:
    any of them
}