rule TTP_XOR_WriteProcessMemory_cf45 {
  strings:
    $key_cf45 = { 98 37 [2] aa 15 [2] ac 20 [2] 82 20 [2] bd 3c }

  condition:
    any of them
}