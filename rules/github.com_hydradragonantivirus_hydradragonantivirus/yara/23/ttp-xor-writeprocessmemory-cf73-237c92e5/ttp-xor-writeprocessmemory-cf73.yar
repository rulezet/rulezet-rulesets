rule TTP_XOR_WriteProcessMemory_cf73 {
  strings:
    $key_cf73 = { 98 01 [2] aa 23 [2] ac 16 [2] 82 16 [2] bd 0a }

  condition:
    any of them
}