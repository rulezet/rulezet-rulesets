rule TTP_XOR_WriteProcessMemory_cf51 {
  strings:
    $key_cf51 = { 98 23 [2] aa 01 [2] ac 34 [2] 82 34 [2] bd 28 }

  condition:
    any of them
}