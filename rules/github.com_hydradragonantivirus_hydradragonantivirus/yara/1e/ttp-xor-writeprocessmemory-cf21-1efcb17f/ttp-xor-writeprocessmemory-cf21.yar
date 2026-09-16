rule TTP_XOR_WriteProcessMemory_cf21 {
  strings:
    $key_cf21 = { 98 53 [2] aa 71 [2] ac 44 [2] 82 44 [2] bd 58 }

  condition:
    any of them
}