rule TTP_XOR_WriteProcessMemory_cf76 {
  strings:
    $key_cf76 = { 98 04 [2] aa 26 [2] ac 13 [2] 82 13 [2] bd 0f }

  condition:
    any of them
}