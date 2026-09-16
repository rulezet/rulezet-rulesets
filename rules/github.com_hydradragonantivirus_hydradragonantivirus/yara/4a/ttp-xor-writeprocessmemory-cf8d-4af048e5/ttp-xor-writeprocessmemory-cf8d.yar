rule TTP_XOR_WriteProcessMemory_cf8d {
  strings:
    $key_cf8d = { 98 ff [2] aa dd [2] ac e8 [2] 82 e8 [2] bd f4 }

  condition:
    any of them
}