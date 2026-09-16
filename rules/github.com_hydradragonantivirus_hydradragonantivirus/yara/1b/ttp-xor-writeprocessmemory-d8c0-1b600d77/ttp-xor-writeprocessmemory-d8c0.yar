rule TTP_XOR_WriteProcessMemory_d8c0 {
  strings:
    $key_d8c0 = { 8f b2 [2] bd 90 [2] bb a5 [2] 95 a5 [2] aa b9 }

  condition:
    any of them
}