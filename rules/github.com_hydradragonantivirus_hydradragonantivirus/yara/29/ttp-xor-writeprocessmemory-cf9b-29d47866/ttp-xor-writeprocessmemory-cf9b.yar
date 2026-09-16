rule TTP_XOR_WriteProcessMemory_cf9b {
  strings:
    $key_cf9b = { 98 e9 [2] aa cb [2] ac fe [2] 82 fe [2] bd e2 }

  condition:
    any of them
}