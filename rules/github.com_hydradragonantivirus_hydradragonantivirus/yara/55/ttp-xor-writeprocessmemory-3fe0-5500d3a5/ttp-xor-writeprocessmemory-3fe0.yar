rule TTP_XOR_WriteProcessMemory_3fe0 {
  strings:
    $key_3fe0 = { 68 92 [2] 5a b0 [2] 5c 85 [2] 72 85 [2] 4d 99 }

  condition:
    any of them
}