rule TTP_XOR_WriteProcessMemory_cf14 {
  strings:
    $key_cf14 = { 98 66 [2] aa 44 [2] ac 71 [2] 82 71 [2] bd 6d }

  condition:
    any of them
}