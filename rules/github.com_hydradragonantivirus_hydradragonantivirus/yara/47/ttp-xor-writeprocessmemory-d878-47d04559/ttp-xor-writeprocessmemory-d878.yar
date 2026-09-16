rule TTP_XOR_WriteProcessMemory_d878 {
  strings:
    $key_d878 = { 8f 0a [2] bd 28 [2] bb 1d [2] 95 1d [2] aa 01 }

  condition:
    any of them
}