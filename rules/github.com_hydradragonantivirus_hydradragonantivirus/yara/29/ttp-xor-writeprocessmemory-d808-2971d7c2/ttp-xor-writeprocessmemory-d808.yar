rule TTP_XOR_WriteProcessMemory_d808 {
  strings:
    $key_d808 = { 8f 7a [2] bd 58 [2] bb 6d [2] 95 6d [2] aa 71 }

  condition:
    any of them
}