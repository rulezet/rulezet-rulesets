rule TTP_XOR_WriteProcessMemory_cf26 {
  strings:
    $key_cf26 = { 98 54 [2] aa 76 [2] ac 43 [2] 82 43 [2] bd 5f }

  condition:
    any of them
}