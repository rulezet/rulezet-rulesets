rule TTP_XOR_WriteProcessMemory_cf30 {
  strings:
    $key_cf30 = { 98 42 [2] aa 60 [2] ac 55 [2] 82 55 [2] bd 49 }

  condition:
    any of them
}