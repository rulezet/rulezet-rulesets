rule TTP_XOR_WriteProcessMemory_e756 {
  strings:
    $key_e756 = { b0 24 [2] 82 06 [2] 84 33 [2] aa 33 [2] 95 2f }

  condition:
    any of them
}