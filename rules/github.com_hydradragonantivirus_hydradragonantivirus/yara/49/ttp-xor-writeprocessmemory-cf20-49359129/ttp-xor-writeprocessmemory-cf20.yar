rule TTP_XOR_WriteProcessMemory_cf20 {
  strings:
    $key_cf20 = { 98 52 [2] aa 70 [2] ac 45 [2] 82 45 [2] bd 59 }

  condition:
    any of them
}