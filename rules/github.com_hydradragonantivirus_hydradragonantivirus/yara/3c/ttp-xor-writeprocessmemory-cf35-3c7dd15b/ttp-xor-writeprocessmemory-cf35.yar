rule TTP_XOR_WriteProcessMemory_cf35 {
  strings:
    $key_cf35 = { 98 47 [2] aa 65 [2] ac 50 [2] 82 50 [2] bd 4c }

  condition:
    any of them
}