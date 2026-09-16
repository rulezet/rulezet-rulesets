rule TTP_XOR_WriteProcessMemory_d840 {
  strings:
    $key_d840 = { 8f 32 [2] bd 10 [2] bb 25 [2] 95 25 [2] aa 39 }

  condition:
    any of them
}