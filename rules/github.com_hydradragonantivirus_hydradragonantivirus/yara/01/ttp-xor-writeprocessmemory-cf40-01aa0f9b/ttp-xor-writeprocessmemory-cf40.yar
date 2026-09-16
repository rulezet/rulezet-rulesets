rule TTP_XOR_WriteProcessMemory_cf40 {
  strings:
    $key_cf40 = { 98 32 [2] aa 10 [2] ac 25 [2] 82 25 [2] bd 39 }

  condition:
    any of them
}