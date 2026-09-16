rule TTP_XOR_WriteProcessMemory_cf48 {
  strings:
    $key_cf48 = { 98 3a [2] aa 18 [2] ac 2d [2] 82 2d [2] bd 31 }

  condition:
    any of them
}