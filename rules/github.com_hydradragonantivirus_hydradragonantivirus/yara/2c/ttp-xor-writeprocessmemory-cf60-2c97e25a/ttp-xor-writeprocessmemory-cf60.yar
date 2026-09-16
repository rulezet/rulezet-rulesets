rule TTP_XOR_WriteProcessMemory_cf60 {
  strings:
    $key_cf60 = { 98 12 [2] aa 30 [2] ac 05 [2] 82 05 [2] bd 19 }

  condition:
    any of them
}