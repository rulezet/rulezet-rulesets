rule TTP_XOR_WriteProcessMemory_cf11 {
  strings:
    $key_cf11 = { 98 63 [2] aa 41 [2] ac 74 [2] 82 74 [2] bd 68 }

  condition:
    any of them
}