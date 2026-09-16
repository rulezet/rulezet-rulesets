rule TTP_XOR_WriteProcessMemory_d848 {
  strings:
    $key_d848 = { 8f 3a [2] bd 18 [2] bb 2d [2] 95 2d [2] aa 31 }

  condition:
    any of them
}