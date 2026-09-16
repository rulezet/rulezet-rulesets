rule TTP_XOR_WriteProcessMemory_cf84 {
  strings:
    $key_cf84 = { 98 f6 [2] aa d4 [2] ac e1 [2] 82 e1 [2] bd fd }

  condition:
    any of them
}