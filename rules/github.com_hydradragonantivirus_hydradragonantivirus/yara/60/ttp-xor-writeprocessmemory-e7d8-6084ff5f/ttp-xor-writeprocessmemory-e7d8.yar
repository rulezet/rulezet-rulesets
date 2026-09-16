rule TTP_XOR_WriteProcessMemory_e7d8 {
  strings:
    $key_e7d8 = { b0 aa [2] 82 88 [2] 84 bd [2] aa bd [2] 95 a1 }

  condition:
    any of them
}