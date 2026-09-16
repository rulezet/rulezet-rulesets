rule TTP_XOR_WriteProcessMemory_cf91 {
  strings:
    $key_cf91 = { 98 e3 [2] aa c1 [2] ac f4 [2] 82 f4 [2] bd e8 }

  condition:
    any of them
}