rule TTP_XOR_WriteProcessMemory_cfa5 {
  strings:
    $key_cfa5 = { 98 d7 [2] aa f5 [2] ac c0 [2] 82 c0 [2] bd dc }

  condition:
    any of them
}