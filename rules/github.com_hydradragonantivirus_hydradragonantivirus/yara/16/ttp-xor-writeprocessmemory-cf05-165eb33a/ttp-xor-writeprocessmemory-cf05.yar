rule TTP_XOR_WriteProcessMemory_cf05 {
  strings:
    $key_cf05 = { 98 77 [2] aa 55 [2] ac 60 [2] 82 60 [2] bd 7c }

  condition:
    any of them
}