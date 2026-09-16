rule TTP_XOR_WriteProcessMemory_cf24 {
  strings:
    $key_cf24 = { 98 56 [2] aa 74 [2] ac 41 [2] 82 41 [2] bd 5d }

  condition:
    any of them
}