rule TTP_XOR_WriteProcessMemory_cf80 {
  strings:
    $key_cf80 = { 98 f2 [2] aa d0 [2] ac e5 [2] 82 e5 [2] bd f9 }

  condition:
    any of them
}