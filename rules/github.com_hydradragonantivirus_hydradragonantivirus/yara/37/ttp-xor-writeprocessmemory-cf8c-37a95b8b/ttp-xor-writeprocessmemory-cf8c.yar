rule TTP_XOR_WriteProcessMemory_cf8c {
  strings:
    $key_cf8c = { 98 fe [2] aa dc [2] ac e9 [2] 82 e9 [2] bd f5 }

  condition:
    any of them
}