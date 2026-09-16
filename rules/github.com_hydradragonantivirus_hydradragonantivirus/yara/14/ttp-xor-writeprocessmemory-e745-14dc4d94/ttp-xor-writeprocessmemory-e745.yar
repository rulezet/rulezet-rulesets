rule TTP_XOR_WriteProcessMemory_e745 {
  strings:
    $key_e745 = { b0 37 [2] 82 15 [2] 84 20 [2] aa 20 [2] 95 3c }

  condition:
    any of them
}