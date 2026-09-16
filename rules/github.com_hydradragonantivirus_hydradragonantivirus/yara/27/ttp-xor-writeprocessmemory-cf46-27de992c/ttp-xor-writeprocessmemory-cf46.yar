rule TTP_XOR_WriteProcessMemory_cf46 {
  strings:
    $key_cf46 = { 98 34 [2] aa 16 [2] ac 23 [2] 82 23 [2] bd 3f }

  condition:
    any of them
}