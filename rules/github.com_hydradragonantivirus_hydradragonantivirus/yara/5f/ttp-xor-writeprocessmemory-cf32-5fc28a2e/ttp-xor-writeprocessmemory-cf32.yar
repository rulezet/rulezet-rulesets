rule TTP_XOR_WriteProcessMemory_cf32 {
  strings:
    $key_cf32 = { 98 40 [2] aa 62 [2] ac 57 [2] 82 57 [2] bd 4b }

  condition:
    any of them
}