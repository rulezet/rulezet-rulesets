rule TTP_XOR_WriteProcessMemory_cfa3 {
  strings:
    $key_cfa3 = { 98 d1 [2] aa f3 [2] ac c6 [2] 82 c6 [2] bd da }

  condition:
    any of them
}