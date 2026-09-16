rule TTP_XOR_WriteProcessMemory_d8c3 {
  strings:
    $key_d8c3 = { 8f b1 [2] bd 93 [2] bb a6 [2] 95 a6 [2] aa ba }

  condition:
    any of them
}