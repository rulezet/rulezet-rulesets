rule TTP_XOR_WriteProcessMemory_cf16 {
  strings:
    $key_cf16 = { 98 64 [2] aa 46 [2] ac 73 [2] 82 73 [2] bd 6f }

  condition:
    any of them
}