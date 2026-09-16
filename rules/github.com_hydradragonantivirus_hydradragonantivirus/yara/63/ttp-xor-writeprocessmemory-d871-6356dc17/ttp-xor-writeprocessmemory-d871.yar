rule TTP_XOR_WriteProcessMemory_d871 {
  strings:
    $key_d871 = { 8f 03 [2] bd 21 [2] bb 14 [2] 95 14 [2] aa 08 }

  condition:
    any of them
}