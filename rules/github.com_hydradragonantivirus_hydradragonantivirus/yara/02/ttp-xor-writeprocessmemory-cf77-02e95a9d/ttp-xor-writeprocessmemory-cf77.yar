rule TTP_XOR_WriteProcessMemory_cf77 {
  strings:
    $key_cf77 = { 98 05 [2] aa 27 [2] ac 12 [2] 82 12 [2] bd 0e }

  condition:
    any of them
}