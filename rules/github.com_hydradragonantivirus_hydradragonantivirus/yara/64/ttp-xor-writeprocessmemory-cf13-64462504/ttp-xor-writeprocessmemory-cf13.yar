rule TTP_XOR_WriteProcessMemory_cf13 {
  strings:
    $key_cf13 = { 98 61 [2] aa 43 [2] ac 76 [2] 82 76 [2] bd 6a }

  condition:
    any of them
}