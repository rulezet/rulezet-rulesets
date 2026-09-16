rule TTP_XOR_WriteProcessMemory_cf9d {
  strings:
    $key_cf9d = { 98 ef [2] aa cd [2] ac f8 [2] 82 f8 [2] bd e4 }

  condition:
    any of them
}