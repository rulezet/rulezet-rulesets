rule TTP_XOR_WriteProcessMemory_cf65 {
  strings:
    $key_cf65 = { 98 17 [2] aa 35 [2] ac 00 [2] 82 00 [2] bd 1c }

  condition:
    any of them
}