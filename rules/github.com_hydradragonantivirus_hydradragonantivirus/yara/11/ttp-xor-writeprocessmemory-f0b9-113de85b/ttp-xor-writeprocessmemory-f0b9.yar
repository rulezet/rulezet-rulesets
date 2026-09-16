rule TTP_XOR_WriteProcessMemory_f0b9 {
  strings:
    $key_f0b9 = { a7 cb [2] 95 e9 [2] 93 dc [2] bd dc [2] 82 c0 }

  condition:
    any of them
}