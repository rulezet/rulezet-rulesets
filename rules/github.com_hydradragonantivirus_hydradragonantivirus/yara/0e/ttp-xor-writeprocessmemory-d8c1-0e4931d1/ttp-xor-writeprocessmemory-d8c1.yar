rule TTP_XOR_WriteProcessMemory_d8c1 {
  strings:
    $key_d8c1 = { 8f b3 [2] bd 91 [2] bb a4 [2] 95 a4 [2] aa b8 }

  condition:
    any of them
}