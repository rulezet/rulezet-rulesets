rule TTP_XOR_WriteProcessMemory_cf55 {
  strings:
    $key_cf55 = { 98 27 [2] aa 05 [2] ac 30 [2] 82 30 [2] bd 2c }

  condition:
    any of them
}