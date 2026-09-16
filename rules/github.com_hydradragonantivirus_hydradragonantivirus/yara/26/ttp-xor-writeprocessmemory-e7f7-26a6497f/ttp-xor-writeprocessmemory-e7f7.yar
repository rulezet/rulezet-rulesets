rule TTP_XOR_WriteProcessMemory_e7f7 {
  strings:
    $key_e7f7 = { b0 85 [2] 82 a7 [2] 84 92 [2] aa 92 [2] 95 8e }

  condition:
    any of them
}