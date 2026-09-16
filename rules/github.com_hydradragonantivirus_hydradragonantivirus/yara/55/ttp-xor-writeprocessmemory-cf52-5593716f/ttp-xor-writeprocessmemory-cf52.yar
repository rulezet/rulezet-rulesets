rule TTP_XOR_WriteProcessMemory_cf52 {
  strings:
    $key_cf52 = { 98 20 [2] aa 02 [2] ac 37 [2] 82 37 [2] bd 2b }

  condition:
    any of them
}