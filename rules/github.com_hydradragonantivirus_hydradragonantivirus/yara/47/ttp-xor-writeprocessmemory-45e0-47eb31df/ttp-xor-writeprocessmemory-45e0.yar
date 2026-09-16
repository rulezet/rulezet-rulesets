rule TTP_XOR_WriteProcessMemory_45e0 {
  strings:
    $key_45e0 = { 12 92 [2] 20 b0 [2] 26 85 [2] 08 85 [2] 37 99 }

  condition:
    any of them
}